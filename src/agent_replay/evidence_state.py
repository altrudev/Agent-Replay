"""Bounded offline evidence-state v1. No incident-v2 semantics are changed."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from datetime import datetime, timezone

from . import strict_json as json

SCHEMA = 'agent-replay.evidence-state.v1'
MAX_BYTES = 2_000_000
MAX_EVENTS = 512
MAX_EDGES = 2048
MAX_OUTPUT = 2_000_000
MAX_DEPTH = 12
TIME = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$')


def timestamp(value):
    """Integer epoch ns or strict aware RFC3339, without floating point."""
    if type(value) is int and -(2**63) <= value < 2**63:
        return value
    if not isinstance(value, str) or not (match := TIME.fullmatch(value)):
        raise ValueError('time requires aware RFC3339 (up to 9 decimals) or integer ns')
    zone = match[3]
    if zone != 'Z' and (int(zone[1:3]) > 23 or int(zone[4:]) > 59 or zone == '-00:00'):
        raise ValueError('invalid or unknown timezone')
    dt = datetime.fromisoformat(match[1] + ('+00:00' if zone == 'Z' else zone))
    delta = dt.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or '').ljust(9, '0'))


def canonical(value):
    # v1 accepts only integers, strings, arrays, objects, booleans and null.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')


def bounded(value):
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > 100_000:
            raise ValueError('structure budget exceeded')
        if isinstance(item, dict):
            if not all(isinstance(k, str) and len(k) <= 256 for k in item):
                raise ValueError('invalid object key')
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if len(item) > 4096:
                raise ValueError('string budget exceeded')
        elif item is not None and type(item) not in (bool, int):
            raise ValueError('unsupported JSON scalar')
        elif type(item) is int and not -(2**63) <= item < 2**63:
            raise ValueError('integer out of range')


def read_local(path, limit=MAX_BYTES):
    """Open each path component without following symlinks, then bounded read."""
    parts = os.path.abspath(path).split(os.sep)[1:]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(parts):
            new = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          (os.O_DIRECTORY if index < len(parts) - 1 else 0), dir_fd=fd)
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('regular bounded file required')
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(chunks)))
            if not chunk:
                return bytes(chunks)
            chunks.extend(chunk)
        raise ValueError('input byte budget exceeded')
    finally:
        os.close(fd)


def decode(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('input byte budget exceeded')
    # Preflight nesting before the recursive JSON parser; account for quoted braces.
    depth = 0
    quoted = escaped = False
    for char in raw.decode('utf-8'):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('structure budget exceeded')
        elif char in ']}':
            depth -= 1
    try:
        value = json.loads(raw)
    except ValueError:
        raise ValueError('invalid evidence JSON (including duplicate keys)') from None
    bounded(value)
    return value


def fields(obj, required, optional=()):
    if not isinstance(obj, dict) or set(obj) - set(required) - set(optional) or set(required) - set(obj):
        raise ValueError('missing or unknown critical fields')
    if 'key_id' in obj:
        label(obj['key_id'])
    if 'signature' in obj and (not isinstance(obj['signature'], str) or not re.fullmatch(r'[a-f0-9]{64}', obj['signature'])):
        raise ValueError('signature requires lowercase SHA256 hex')


def label(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError('nonempty bounded label required')


def signable(context, kind, record):
    return canonical({'schema': SCHEMA, 'context_id': context, 'kind': kind,
                      'record': {k: v for k, v in record.items() if k != 'signature'}})


def signature(context, kind, record, key):
    """Producer helper; key bytes are never included in the evidence or result."""
    return hmac.new(key, signable(context, kind, record), hashlib.sha256).hexdigest()


def authenticated(context, kind, record, anchors):
    sig = record.get('signature')
    anchor = anchors.get(record.get('key_id'))
    if not anchor or anchor['source'] != record['source'] or not isinstance(sig, str):
        return False
    return hmac.compare_digest(signature(context, kind, record, anchor['key']), sig)


def assess(document, *, trust_anchors=None):
    """Assess one decision. Anchors: key_id -> {source: str, key: bytes >=32}.

    Anchor possession attests records from that source, not real-world identity.
    No caller-provided verified flag, embedded key or precedence rule is accepted.
    """
    bounded(document)
    if len(canonical(document)) > MAX_BYTES:
        raise ValueError('input byte budget exceeded')
    fields(document, ('schema', 'context_id', 'decision', 'events', 'receipts', 'coverage'))
    if document['schema'] != SCHEMA:
        raise ValueError('unsupported schema')
    label(document['context_id'])
    context = document['context_id']
    anchors = trust_anchors or {}
    for key_id, anchor in anchors.items():
        label(key_id)
        fields(anchor, ('source', 'key'))
        label(anchor['source'])
        if not isinstance(anchor['key'], bytes) or len(anchor['key']) < 32:
            raise ValueError('trust key must contain at least 32 bytes')
    decision = document['decision']
    fields(decision, ('actor_instance_id', 'at', 'action', 'subject', 'channel', 'source', 'since', 'credential'))
    for name in ('actor_instance_id', 'action', 'subject', 'channel', 'source', 'credential'):
        label(decision[name])
    horizon, since = timestamp(decision['at']), timestamp(decision['since'])
    if since > horizon:
        raise ValueError('invalid decision interval')
    for name in ('events', 'receipts', 'coverage'):
        if not isinstance(document[name], list):
            raise ValueError('record array required')
    if len(document['events']) > MAX_EVENTS or len(document['receipts']) + len(document['coverage']) > MAX_EDGES:
        raise ValueError('record/edge budget exceeded')
    events = {}
    times = {}
    for event in document['events']:
        fields(event, ('evidence_id', 'source', 'subject', 'actor_instance_id', 'action', 'channel', 'kind', 'scope', 'observed_at', 'ingested_at'), ('event_at', 'occurred_at', 'key_id', 'signature'))
        if ('event_at' in event) == ('occurred_at' in event):
            raise ValueError('exactly one occurrence clock required')
        for name in ('evidence_id', 'source', 'subject', 'actor_instance_id', 'action', 'channel'):
            label(event[name])
        if event['kind'] not in ('approval', 'revocation', 'assertion'):
            raise ValueError('unsupported event kind')
        fields(event['scope'], ('credential', 'operation', 'resource', 'valid_until'))
        for name in ('credential', 'operation', 'resource'):
            label(event['scope'][name])
        timestamp(event['scope']['valid_until'])
        eid = event['evidence_id']
        if eid in events:
            raise ValueError('duplicate evidence id')
        clocks = tuple(timestamp(event[n]) for n in (('event_at' if 'event_at' in event else 'occurred_at'), 'observed_at', 'ingested_at'))
        if not clocks[0] <= clocks[1] <= clocks[2]:
            raise ValueError('inconsistent three-clock ordering')
        events[eid], times[eid] = event, clocks
    receipts = {}
    for receipt in document['receipts']:
        fields(receipt, ('evidence_id', 'actor_instance_id', 'source', 'mode', 'received_at', 'observed_at', 'ingested_at', 'evidence_sha256'), ('signature', 'key_id'))
        label(receipt['evidence_id'])
        if receipt['evidence_id'] not in events or receipt['mode'] not in ('delivered', 'consulted'):
            raise ValueError('invalid receipt reference/mode')
        expected_digest = hashlib.sha256(signable(context, 'event', events[receipt['evidence_id']])).hexdigest()
        if receipt['evidence_sha256'] != expected_digest:
            raise ValueError('receipt evidence content binding mismatch')
        label(receipt['actor_instance_id'])
        label(receipt['source'])
        clocks = tuple(timestamp(receipt[n]) for n in ('received_at', 'observed_at', 'ingested_at'))
        if not times[receipt['evidence_id']][0] <= clocks[0] <= clocks[1] <= clocks[2]:
            raise ValueError('inconsistent receipt clocks')
        receipts.setdefault(receipt['evidence_id'], []).append((receipt, clocks))
    rows = []
    for eid, event in sorted(events.items()):
        available = [r for r, t in receipts.get(eid, []) if r['actor_instance_id'] == decision['actor_instance_id'] and max(t[:2]) <= horizon]
        auth = authenticated(context, 'event', event, anchors)
        if max(times[eid][:2]) > horizon:
            state = 'LATER_OBSERVED'
        elif any(authenticated(context, 'receipt', r, anchors) for r in available):
            state = 'KNOWN'
        elif available:
            state = 'MAYBE_AVAILABLE'
        else:
            state = 'NOT_ESTABLISHED'
        rows.append({'evidence_ref': hashlib.sha256(eid.encode()).hexdigest(), 'kind': event['kind'], 'knowledge': state,
                     'event_at_ns': times[eid][0], 'observed_at_ns': times[eid][1], 'ingested_at_ns': times[eid][2],
                     'scope_sha256': hashlib.sha256(canonical(event['scope'])).hexdigest(),
                     'receipt_provenance': sorted(hashlib.sha256(canonical(r)).hexdigest() for r, _ in receipts.get(eid, [])),
                     'authenticity': 'AUTHENTICATED_SOURCE' if auth else 'SUPPLIED_ASSERTION',
                     'provenance_sha256': hashlib.sha256(canonical(event)).hexdigest()})
    # Preserve contradictory records. Neither later timestamp nor list order grants
    # precedence. Revocation freshness remains unknown without a policy protocol.
    scoped = {}
    for eid, event in events.items():
        scoped[eid] = (all(event[n] == decision[n] for n in
                           ('source', 'actor_instance_id', 'action', 'subject', 'channel'))
                       and event['scope']['credential'] == decision['credential']
                       and event['scope']['operation'] == decision['action']
                       and event['scope']['resource'] == decision['subject'])
    authenticated_events = {eid for eid, row in zip(sorted(events), rows)
                            if row['authenticity'] == 'AUTHENTICATED_SOURCE'}
    known_authenticated = {eid for eid, row in zip(sorted(events), rows)
                           if row['knowledge'] == 'KNOWN' and eid in authenticated_events}
    revocations = {eid for eid in known_authenticated if scoped[eid] and events[eid]['kind'] == 'revocation'}
    for eid, row in zip(sorted(events), rows):
        event = events[eid]
        if not scoped[eid]:
            role = 'OUT_OF_SCOPE'
        elif eid not in known_authenticated:
            role = 'NOT_ESTABLISHED'
        elif event['kind'] == 'revocation':
            role = 'REVOCATION_EVIDENCED'
        elif event['kind'] != 'approval':
            role = 'NOT_AUTHORITY_EVIDENCE'
        elif timestamp(event['scope']['valid_until']) < horizon:
            role = 'EXPIRED_APPROVAL'
        elif revocations:
            role = 'CONFLICTING_REVOCATION'
        else:
            role = 'APPROVAL_EVIDENCED_FRESHNESS_NOT_ESTABLISHED'
        row['authority_evidence'] = role
    coverage = []
    complete = False
    for manifest in document['coverage']:
        fields(manifest, ('manifest_id', 'source', 'actor_instance_id', 'channel', 'action', 'subject', 'start', 'end', 'observed_at', 'ingested_at', 'complete', 'evidence_ids'), ('signature', 'key_id'))
        for name in ('manifest_id', 'source', 'actor_instance_id', 'channel', 'action', 'subject'):
            label(manifest[name])
        start, end, observed, ingested = (timestamp(manifest[n]) for n in ('start', 'end', 'observed_at', 'ingested_at'))
        if not start <= end <= observed <= ingested or type(manifest['complete']) is not bool:
            raise ValueError('invalid coverage clocks/completeness')
        ids = manifest['evidence_ids']
        if not isinstance(ids, list) or len(ids) > MAX_EVENTS or not all(isinstance(x, str) for x in ids) or len(ids) != len(set(ids)):
            raise ValueError('invalid coverage evidence ids')
        for evidence_id in ids:
            label(evidence_id)
        scope_match = all(manifest[n] == decision[n] for n in ('source', 'actor_instance_id', 'channel', 'action', 'subject'))
        expected = sorted(eid for eid, e in events.items() if all(e[n] == manifest[n] for n in ('source', 'actor_instance_id', 'channel', 'action', 'subject')) and start <= times[eid][0] <= end)
        auth = authenticated(context, 'coverage', manifest, anchors)
        status = 'AUTHENTICATED_COVERAGE' if auth else 'SUPPLIED_ASSERTION'
        # A signed ID list does not authenticate the records behind those IDs.
        # Check every listed member, including ones tampered out of scope/time;
        # exact membership then also covers every supplied scoped event.
        members_authenticated = all(eid in authenticated_events for eid in ids)
        usable = auth and scope_match and manifest['complete'] and start == since and end == horizon and sorted(ids) == expected and members_authenticated
        complete |= usable
        coverage.append({'manifest_ref': hashlib.sha256(manifest['manifest_id'].encode()).hexdigest(), 'authentication': status, 'usable_for_exact_horizon': bool(usable), 'provenance_sha256': hashlib.sha256(canonical(manifest)).hexdigest()})
    relevant = [e for e in events.values() if all(e[n] == decision[n] for n in ('source', 'actor_instance_id', 'channel', 'action', 'subject')) and since <= times[e['evidence_id']][0] <= horizon and e['kind'] == 'approval']
    result = {'schema': SCHEMA, 'ruleset': '1', 'canonical_sha256': hashlib.sha256(canonical(document)).hexdigest(),
              'trust_binding_sha256': hashlib.sha256(canonical({k: {'source': a['source'], 'key_sha256': hashlib.sha256(a['key']).hexdigest()} for k, a in sorted(anchors.items())})).hexdigest(),
              'evidence': rows, 'coverage': sorted(coverage, key=lambda x: (x['manifest_ref'], x['provenance_sha256'])),
              'approval_absence': 'ABSENT_IN_EXACT_COVERED_SCOPE' if complete and not relevant else 'NOT_ESTABLISHED',
              'authority': 'NOT_ESTABLISHED', 'identity': 'NOT_ESTABLISHED', 'causality': 'NOT_ESTABLISHED',
              'limitations': ['Receipt proves delivery/consultation assertion from trusted source, not comprehension.', 'No precedence between contradictory approvals/revocations; credential freshness and authorization require an external policy.', 'Coverage is retrospective; it does not establish actor knowledge.', 'Authenticated coverage supports absence only when every listed member is independently source-authenticated and the list exactly matches supplied scoped events. The manifest attests its producer\'s completeness assertion, not external truth or source honesty.', 'No public share format; labels are hashed, but timestamps and digests can still be sensitive.']}
    if len(canonical(result)) + 1 > MAX_OUTPUT:
        raise ValueError('output budget exceeded')
    return result


def assess_bytes(raw, *, trust_anchors=None):
    result = assess(decode(raw), trust_anchors=trust_anchors)
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    if len(canonical(result)) + 1 > MAX_OUTPUT:
        raise ValueError('output budget exceeded')
    return result
