"""Customer-owned offline workspace. Apache-2.0; no network or global enrollment."""
from __future__ import annotations
import copy
import hashlib
import hmac
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from . import evidence_state as es

LEGACY_LIMIT = 32_000_000
WARNING = 'Customer attestation is not independent proof. Source honesty, identity, authority and causality remain unestablished.'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def private_umask():
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)


class Workspace:
    """Pinned directory descriptors, no symlinks, strict owner-only persistence.

    Same-UID malicious processes are outside the local filesystem trust boundary.
    One process holds an exclusive workspace lock, released by close().
    """
    def __init__(self, path, *, create=False):
        import fcntl
        path = os.fspath(path)
        if '..' in Path(path).parts:
            raise ValueError('Workspace traversal is not permitted')
        parts = Path(os.path.abspath(path)).parts[1:]
        if not parts:
            raise ValueError('Choose a private workspace directory')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        self.fd = None
        try:
            for index, part in enumerate(parts):
                parent = os.fstat(fd)
                if parent.st_mode & 0o002:
                    raise ValueError('Workspace ancestors must not be world writable')
                if create and index == len(parts) - 1:
                    with private_umask():
                        try:
                            os.mkdir(part, 0o700, dir_fd=fd)
                        except FileExistsError:
                            pass
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('Workspace must be owned by you with permissions 0700')
            self.fd = fd
            fd = None
            self.lock = self._open('lock', os.O_RDWR | os.O_CREAT)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                self.state = self._read('state.json')
            except FileNotFoundError:
                if not create:
                    raise ValueError('Workspace is not initialized') from None
                self.state = {'schema': 'agent-replay.customer-workspace.v1', 'sources': {}, 'keys': {}, 'reports': {}}
                self._save()
            if self.state.get('schema') != 'agent-replay.customer-workspace.v1':
                raise ValueError('Unsupported workspace schema')
        except BaseException:
            if fd is not None:
                os.close(fd)
            self.close()
            raise

    def close(self):
        if getattr(self, 'lock', None) is not None:
            os.close(self.lock)
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _open(self, name, flags):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
            raise ValueError('Invalid internal filename')
        truncate = bool(flags & os.O_TRUNC)
        flags &= ~os.O_TRUNC
        with private_umask():
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(fd)
            raise ValueError('Private regular owner-only file required')
        if truncate:
            os.ftruncate(fd, 0)
        return fd

    def _read(self, name):
        fd = self._open(name, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(128_000_001)
        if len(raw) > 128_000_000:
            raise ValueError('Workspace storage budget exceeded')
        from .strict_json import loads
        return loads(raw)

    def _write(self, name, value):
        raw = es.canonical(value)
        if len(raw) > 128_000_000:
            raise ValueError('Workspace storage budget exceeded; use another workspace')
        temporary = 'pending-' + secrets.token_hex(16)
        fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def _save(self):
        self._write('state.json', self.state)

    def public(self):
        return copy.deepcopy(self.state)

    def enroll(self, source, mode='SELF_ATTESTED'):
        es.label(source)
        if mode != 'SELF_ATTESTED':
            raise ValueError('EXTERNAL_VERIFIED requires an independent verifier; this product cannot enroll one')
        if source in self.state['sources']:
            raise ValueError('Source already enrolled')
        self.state['sources'][source] = {'mode': mode, 'provenance': 'CUSTOMER_ATTESTED', 'active_key': None}
        return self.rotate(source)

    def rotate(self, source):
        if source not in self.state['sources']:
            raise ValueError('Unknown source')
        entry = self.state['sources'][source]
        previous = entry['active_key']
        key_id = secrets.token_hex(16)
        self._write('key-' + key_id, {'key_hex': secrets.token_bytes(32).hex()})
        if previous:
            self.state['keys'][previous]['status'] = 'RETIRED'
        self.state['keys'][key_id] = {'source': source, 'status': 'ACTIVE', 'predecessor': previous, 'provenance': 'CUSTOMER_ATTESTED'}
        entry['active_key'] = key_id
        self._save()
        return self.public()

    def revoke(self, key_id, acknowledgement):
        if acknowledgement != 'REVOKE AND DELETE KEY; HISTORICAL VERIFICATION WILL BE UNAVAILABLE':
            raise ValueError('Explicit revocation and permanent deletion acknowledgement required')
        entry = self.state['keys'][key_id]
        if entry['status'] == 'REVOKED':
            raise ValueError('Key already revoked')
        # Delete first: interrupted revocation fails closed when loading anchors.
        os.unlink('key-' + key_id, dir_fd=self.fd)
        entry['status'] = 'REVOKED'
        source = self.state['sources'][entry['source']]
        if source['active_key'] == key_id:
            source['active_key'] = None
        self._save()
        return self.public()

    def _anchors(self, key_ids):
        result = {}
        for key_id in key_ids:
            entry = self.state['keys'].get(key_id)
            if not entry or entry['status'] == 'REVOKED':
                raise ValueError('Verification unavailable: unknown or revoked key')
            key = bytes.fromhex(self._read('key-' + key_id)['key_hex'])
            if len(key) != 32:
                raise ValueError('Invalid local key')
            result[key_id] = {'source': entry['source'], 'key': key}
        return result

    def preview(self, raw, source, *, coverage=False):
        """Prepare exact proposed changes, never overwrite supplied signatures/trust."""
        doc = es.decode(raw)
        es.assess(doc)
        if source not in self.state['sources']:
            raise ValueError('Enroll your own source first')
        key_id = self.state['sources'][source]['active_key']
        if not key_id:
            raise ValueError('Rotate to create an active key first')
        records = []
        for group, kind in [('events', 'event'), ('receipts', 'receipt'), ('coverage', 'coverage')]:
            for index, record in enumerate(doc[group]):
                if record['source'] == source and (coverage or group != 'coverage'):
                    if 'signature' in record or 'key_id' in record:
                        raise ValueError('Selected records already contain trust fields; analyze as supplied instead')
                    record['key_id'] = key_id
                    records.append([group, index, kind])
        if not records:
            raise ValueError('No eligible self-owned records')
        # Adding key_id changes the event binding. Never alter someone else's receipt.
        for receipt in doc['receipts']:
            event = next(e for e in doc['events'] if e['evidence_id'] == receipt['evidence_id'])
            binding = digest(es.signable(doc['context_id'], 'event', event))
            if receipt['evidence_sha256'] != binding:
                if receipt['source'] != source or 'signature' in receipt:
                    raise ValueError('Cannot change supplied third-party receipt binding')
                receipt['evidence_sha256'] = binding
        es.assess(doc)
        review = {'warning': WARNING, 'original_input_sha256': digest(raw), 'source': source,
                  'context_id': doc['context_id'], 'decision': doc['decision'], 'records': records,
                  'proposed_document': doc, 'coverage_explicitly_selected': coverage}
        review['confirmation'] = digest(es.canonical(review))
        return review

    def analyze(self, raw, fmt='evidence', *, review=None, confirmation=None, own=False):
        if fmt == 'evidence':
            doc = es.decode(raw)
            anchors = {}
            attestation = 'SUPPLIED_CLAIMS'
            if review is not None:
                if own is not True or confirmation != review['confirmation']:
                    raise ValueError('Confirm exact preview and self-owned observations')
                expected = self.preview(raw, review['source'], coverage=review['coverage_explicitly_selected'])
                if expected != review:
                    raise ValueError('Preview is stale or changed; review again')
                doc = copy.deepcopy(review['proposed_document'])
                key_id = self.state['sources'][review['source']]['active_key']
                anchors = self._anchors([key_id])
                for group, index, kind in review['records']:
                    record = doc[group][index]
                    record['signature'] = es.signature(doc['context_id'], kind, record, anchors[key_id]['key'])
                attestation = 'CUSTOMER_ATTESTED'
            result = es.assess(doc, trust_anchors=anchors)
            analyzed = es.canonical(doc)
        else:
            if fmt not in ('jsonl', 'otel', 'aps') or len(raw) > LEGACY_LIMIT:
                raise ValueError('Choose a supported format within the upload budget')
            # Fixed private filename; reuse the release CLI's full validation path.
            name = 'legacy-input'
            fd = self._open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
            from .cli import _reconstruct_input
            from .normalize import DEFAULT_MAX_DEPTH, DEFAULT_MAX_EVENTS, DEFAULT_MAX_PARENTS
            try:
                result = _reconstruct_input(SimpleNamespace(input=f'/proc/self/fd/{self.fd}/{name}', format=fmt,
                    max_bytes=LEGACY_LIMIT, max_events=DEFAULT_MAX_EVENTS, max_parents=DEFAULT_MAX_PARENTS,
                    max_depth=DEFAULT_MAX_DEPTH, trace_id=None))
            finally:
                os.unlink(name, dir_fd=self.fd)
            analyzed, doc, anchors, attestation = raw, None, {}, 'SUPPLIED_CLAIMS'
        report = {'schema': 'agent-replay.customer-report.v1', 'format': fmt, 'input_sha256': digest(raw),
                  'analyzed_sha256': digest(analyzed), 'attestation': attestation,
                  'coverage_trust': ('CUSTOMER_SOURCE_AUTHENTICATED' if anchors and any(c['usable_for_exact_horizon'] for c in result.get('coverage', [])) else 'NOT_ESTABLISHED'),
                  'certification': 'NOT_INDEPENDENTLY_VERIFIED', 'warning': WARNING,
                  'key_provenance': {k: copy.deepcopy(self.state['keys'][k]) for k in anchors}, 'result': result}
        report_id = digest(es.canonical(report))
        self._write('report-' + report_id, {'report': report, 'document': doc})
        self.state['reports'][report_id] = {'format': fmt, 'attestation': attestation, 'input_sha256': digest(raw)}
        self._save()
        return {'report_id': report_id, **report}

    def report(self, report_id):
        if report_id not in self.state['reports']:
            raise ValueError('Unknown report')
        return self._read('report-' + report_id)

    def verify(self, report_id, historical=False):
        stored = self.report(report_id)
        report = stored['report']
        ids = list(report['key_provenance'])
        if not ids:
            intact = digest(es.canonical(report)) == report_id
            if report['format'] == 'evidence':
                try:
                    intact = intact and es.assess(stored['document']) == report['result'] and digest(es.canonical(stored['document'])) == report['analyzed_sha256']
                except ValueError:
                    intact = False
            return {'status': 'NO_CUSTOMER_SIGNATURES' if intact else 'MISMATCH', 'report_integrity': intact}
        if any(self.state['keys'][k]['status'] == 'RETIRED' for k in ids) and not historical:
            raise ValueError('Explicit historical verification required for retired keys')
        anchors = self._anchors(ids)
        try:
            result = es.assess(stored['document'], trust_anchors=anchors)
        except ValueError:
            return {'status': 'MISMATCH'}
        valid = result == report['result'] and digest(es.canonical(stored['document'])) == report['analyzed_sha256'] and digest(es.canonical(report)) == report_id
        return {'status': 'REPRODUCED' if valid else 'MISMATCH', 'current_keys': {k: self.state['keys'][k] for k in ids}, 'historical': historical}

    def export(self, report_id, consent=False):
        if consent is not True:
            raise ValueError('Explicit export consent required; digests may still be sensitive')
        report = self.report(report_id)['report']
        result = report['result']
        summary = {'coverage_trust': report['coverage_trust'],
                   'approval_absence': result.get('approval_absence', 'NOT_APPLICABLE'),
                   'evidence_count': len(result.get('evidence', result.get('timeline', []))),
                   'known_receipt_count': sum(e.get('knowledge') == 'KNOWN' for e in result.get('evidence', [])),
                   'reconstruction_status': result.get('reconstruction_status', 'NOT_APPLICABLE')}
        return {'schema': 'agent-replay.customer-export.v1', 'report_id': report_id, 'summary': summary,
                **{k: report[k] for k in ('format', 'input_sha256', 'analyzed_sha256', 'attestation', 'certification')},
                'warning': WARNING, 'raw_evidence': 'OMITTED', 'secrets': 'OMITTED'}

    def diagnostics(self):
        key = secrets.token_bytes(32)
        record = {'source': 'synthetic', 'key_id': 'synthetic'}
        signed = {**record, 'signature': es.signature('diagnostic', 'event', record, key)}
        anchor = {'synthetic': {'source': 'synthetic', 'key': key}}
        checks = {'valid_signature': es.authenticated('diagnostic', 'event', signed, anchor),
                  'tampered_context_rejected': not es.authenticated('other', 'event', signed, anchor),
                  'unsigned_rejected': not es.authenticated('diagnostic', 'event', record, anchor),
                  'wrong_source_rejected': not es.authenticated('diagnostic', 'event', {**signed, 'source': 'fake'}, anchor)}
        for kid, meta in self.state['keys'].items():
            if meta['status'] != 'REVOKED':
                configured = self._anchors([kid])
                probe = {'source': meta['source'], 'key_id': kid}
                probe['signature'] = es.signature('diagnostic', 'event', probe, configured[kid]['key'])
                checks['configured-' + kid] = (es.authenticated('diagnostic', 'event', probe, configured)
                    and not es.authenticated('tampered', 'event', probe, configured))
            else:
                try:
                    os.stat('key-' + kid, dir_fd=self.fd, follow_symlinks=False)
                except FileNotFoundError:
                    checks['revoked-deleted-' + kid] = True
                else:
                    checks['revoked-deleted-' + kid] = False
        return {'schema': 'agent-replay.customer-diagnostics.v1', 'status': 'PASS' if all(checks.values()) else 'FAIL',
                'checks': checks, 'key_lifecycle': copy.deepcopy(self.state['keys']), 'warning': WARNING}
