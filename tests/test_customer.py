"""Adversarial local customer workflow, using synthetic keys only."""
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading

import pytest

from agent_replay.customer import Workspace, digest
from agent_replay.customer_web import Dashboard
from agent_replay import evidence_state as es
from test_evidence_state import fixture

ROOT = Path(__file__).resolve().parents[1]
ACK = 'REVOKE AND DELETE KEY; HISTORICAL VERIFICATION WILL BE UNAVAILABLE'


@pytest.fixture
def private_root():
    # Do not place trusted workspaces under world-writable /tmp.
    p = Path(tempfile.mkdtemp(prefix='.customer-test-', dir=ROOT))
    try:
        yield p
    finally:
        shutil.rmtree(p)


@pytest.fixture
def workspace(private_root):
    with Workspace(private_root / 'workspace', create=True) as w:
        yield w


def test_private_permissions_symlinks_traversal_and_parent(private_root):
    with Workspace(private_root / 'w', create=True) as w:
        w.enroll('audit')
        assert (private_root / 'w').stat().st_mode & 0o777 == 0o700
        for p in (private_root / 'w').iterdir():
            assert p.stat().st_mode & 0o777 == 0o600
        with pytest.raises(OSError):
            Workspace(private_root / 'w')  # exclusive process lock
    with pytest.raises(ValueError):
        Workspace(private_root / 'x' / '..' / 'w')
    (private_root / 'link').symlink_to(private_root / 'w', target_is_directory=True)
    with pytest.raises(OSError):
        Workspace(private_root / 'link')
    bad = private_root / 'public'
    bad.mkdir(mode=0o777)
    bad.chmod(0o777)
    with pytest.raises(ValueError, match='world writable'):
        Workspace(bad / 'child', create=True)
    (private_root / 'w' / 'state.json').chmod(0o644)
    with pytest.raises(ValueError, match='owner-only'):
        Workspace(private_root / 'w')


def attest(w, doc=None, coverage=True):
    raw = es.canonical(doc or fixture())
    review = w.preview(raw, 'audit', coverage=coverage)
    return w.analyze(raw, review=review, confirmation=review['confirmation'], own=True)


def test_attestation_rotation_revocation_and_reproducibility(workspace):
    w = workspace
    w.enroll('audit')
    old = w.state['sources']['audit']['active_key']
    raw = es.canonical(fixture())
    supplied = w.analyze(raw)
    assert supplied['attestation'] == 'SUPPLIED_CLAIMS'
    assert supplied['result']['coverage'][0]['authentication'] == 'SUPPLIED_ASSERTION'
    report = attest(w)
    assert report['attestation'] == 'CUSTOMER_ATTESTED'
    assert report['result']['coverage'][0]['usable_for_exact_horizon'] is True
    assert report['result']['evidence'][0]['knowledge'] == 'KNOWN'
    assert report['certification'] == 'NOT_INDEPENDENTLY_VERIFIED'
    assert report['input_sha256'] == digest(raw)
    assert w.verify(report['report_id'])['status'] == 'REPRODUCED'
    w.rotate('audit')
    assert w.state['keys'][old]['status'] == 'RETIRED'
    with pytest.raises(ValueError, match='historical'):
        w.verify(report['report_id'])
    assert w.verify(report['report_id'], historical=True)['status'] == 'REPRODUCED'
    assert old not in attest(w)['key_provenance']
    with pytest.raises(ValueError):
        w.revoke(old, '')
    w.revoke(old, ACK)
    assert not (Path(f'/proc/self/fd/{w.fd}') / ('key-' + old)).exists()
    with pytest.raises(ValueError, match='revoked'):
        w.verify(report['report_id'], historical=True)
    assert w.report(report['report_id'])['report']['result'] == report['result']
    assert w.diagnostics()['status'] == 'PASS'


def test_conservative_review_no_fake_verifier_no_overwrite(workspace):
    w = workspace
    with pytest.raises(ValueError, match='independent'):
        w.enroll('audit', 'EXTERNAL_VERIFIED')
    w.enroll('audit')
    raw = es.canonical(fixture())
    review = w.preview(raw, 'audit')
    assert review['coverage_explicitly_selected'] is False
    assert all(r[0] != 'coverage' for r in review['records'])
    for own, confirmation in [(False, review['confirmation']), (True, 'fake')]:
        with pytest.raises(ValueError):
            w.analyze(raw, review=review, own=own, confirmation=confirmation)
    changed = fixture()
    changed['context_id'] = 'different-context'
    with pytest.raises(ValueError):
        w.analyze(es.canonical(changed), review=review, own=True, confirmation=review['confirmation'])
    w.rotate('audit')
    with pytest.raises(ValueError, match='stale'):
        w.analyze(raw, review=review, own=True, confirmation=review['confirmation'])
    d = fixture()
    d['events'][0].update(key_id='third-party', signature='a' * 64)
    d['receipts'][0]['evidence_sha256'] = digest(es.signable(d['context_id'], 'event', d['events'][0]))
    # Supplied valid-format signatures remain claims, never silently trusted.
    assert w.analyze(es.canonical(d))['attestation'] == 'SUPPLIED_CLAIMS'
    with pytest.raises(ValueError, match='trust fields'):
        w.preview(es.canonical(d), 'audit')
    d = fixture()
    d['receipts'][0]['source'] = 'third-party'
    with pytest.raises(ValueError, match='third-party'):
        w.preview(es.canonical(d), 'audit')


def test_secrets_export_isolation_and_bound_report(workspace, private_root):
    w = workspace
    w.enroll('audit')
    r = attest(w)
    key_id = w.state['sources']['audit']['active_key']
    secret = w._read('key-' + key_id)['key_hex']
    with pytest.raises(ValueError):
        w.export(r['report_id'])
    exported = w.export(r['report_id'], consent=True)
    assert 'result' not in exported and 'key_provenance' not in exported
    for value in (w.public(), r, exported, w.diagnostics()):
        assert secret not in json.dumps(value)
        assert 'key_hex' not in json.dumps(value)
    with Workspace(private_root / 'other', create=True) as other:
        with pytest.raises(ValueError):
            other.report(r['report_id'])
        other.enroll('audit')
        assert key_id not in other.state['keys']
    stored = w.report(r['report_id'])
    stored['document']['context_id'] = 'tampered'
    w._write('report-' + r['report_id'], stored)
    assert w.verify(r['report_id'])['status'] == 'MISMATCH'


@pytest.mark.parametrize('raw', [b'{', b'{"schema":1,"schema":2}', b'[]', b'NaN', b'[' * 30, b'x' * 2_000_001])
def test_malicious_evidence(workspace, raw):
    with pytest.raises((ValueError, UnicodeError)):
        workspace.analyze(raw)


def test_legacy_formats(workspace):
    for fmt, path in [('jsonl', ROOT / 'examples/refund-750/events.jsonl'),
                      ('otel', ROOT / 'examples/refund-750/otel.json'),
                      ('aps', ROOT / 'tests/fixtures/aps-oracle-safety-check-v1/pass.json')]:
        r = workspace.analyze(path.read_bytes(), fmt)
        assert r['input_sha256'] == digest(path.read_bytes())
        assert r['attestation'] == 'SUPPLIED_CLAIMS'
    with pytest.raises(ValueError):
        workspace.analyze(b'not json', 'jsonl')


@pytest.fixture
def http_dashboard(workspace):
    try:
        server = Dashboard(workspace)
    except PermissionError:
        pytest.skip('Environment prohibits socket creation; real localhost HTTP acceptance remains unverified')
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


class Client:
    def __init__(self, server):
        self.server = server
        self.csrf = ''
        self.cookie = ''

    def request(self, method, path, data=None, headers=None, body=None):
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        h = {'Origin': self.server.origin, 'Content-Type': 'application/json', 'X-Replay-CSRF': self.csrf, 'Cookie': self.cookie}
        h.update(headers or {})
        c.request(method, path, body=body if body is not None else json.dumps(data or {}), headers=h)
        response = c.getresponse()
        raw = response.read().decode()
        result = (response.status, raw, dict(response.getheaders()))
        c.close()
        return result

    def login(self):
        status, raw, headers = self.request('POST', '/api/session', {'token': self.server.bootstrap})
        assert status == 200
        self.csrf = json.loads(raw)['csrf']
        self.cookie = headers['Set-Cookie'].split(';')[0]
        assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']

    def post(self, action, data=None):
        status, raw, headers = self.request('POST', '/api/' + action, data)
        assert status == 200, raw
        return json.loads(raw)


def test_http_customer_click_flow_and_xss(http_dashboard, capsys):
    s = http_dashboard
    c = Client(s)
    status, page, headers = c.request('GET', '/')
    assert status == 200 and '<title>Agent Replay' in page
    assert 'worker-src' in headers['Content-Security-Policy']
    for route in ['home', 'sources', 'import', 'results', 'help']:
        assert f'id="{route}"' in page
    c.login()
    c.post('enroll', {'source': 'audit'})
    hostile = '<img src=x onerror=alert(1)>'
    c.post('enroll', {'source': hostile})
    assert c.request('GET', '/api/state')[0] == 200
    # User labels only go through textContent; never interpolated into HTML.
    js = c.request('GET', '/app.js')[1]
    assert 'innerHTML' not in js and 'textContent' in js and 'setInterval' not in js
    assert hostile not in c.request('GET', '/')[1]
    raw = es.canonical(fixture()).decode()
    supplied = c.post('analyze', {'data': raw})
    review = c.post('preview', {'data': raw, 'source': 'audit', 'coverage': True})
    report = c.post('analyze', {'data': raw, 'attest': True, 'confirmation': review['confirmation'], 'own': True})
    assert report['result']['coverage'][0]['usable_for_exact_horizon'] is True
    assert c.post('report', {'report_id': report['report_id']})['input_sha256'] == digest(raw.encode())
    assert c.post('verify', {'report_id': report['report_id']})['status'] == 'REPRODUCED'
    c.post('rotate', {'source': 'audit'})
    assert c.post('verify', {'report_id': report['report_id'], 'historical': True})['status'] == 'REPRODUCED'
    assert c.post('diagnostics')['status'] == 'PASS'
    exported = c.post('export', {'report_id': report['report_id'], 'consent': True})
    assert exported['raw_evidence'] == exported['secrets'] == 'OMITTED'
    assert c.request('POST', '/api/export', {'report_id': supplied['report_id'], 'consent': False})[0] == 400
    for kid in s.workspace.state['keys']:
        secret = s.workspace._read('key-' + kid)['key_hex']
        assert secret not in json.dumps(report) + json.dumps(exported) + page + c.request('GET', '/api/state')[1]
        assert secret not in capsys.readouterr().out


def test_http_boundaries_uploads_and_one_use_session(http_dashboard):
    s = http_dashboard
    with pytest.raises(ValueError):
        Dashboard(s.workspace, host='0.0.0.0')
    assert s.server_address[0] == '127.0.0.1'
    c = Client(s)
    token = s.bootstrap
    assert c.request('GET', '/api/state')[0] == 403
    for h in [{'Host': 'evil.example'}, {'Origin': 'https://evil.example'}, {'Origin': ''}, {'Service-Worker': 'script'}, {'Sec-Fetch-Site': 'cross-site'}]:
        assert c.request('POST', '/api/session', {'token': token}, h)[0] == 400
    c.login()
    assert c.request('POST', '/api/session', {'token': token})[0] == 403
    assert c.request('POST', '/api/enroll', {'source': 'bad'}, {'X-Replay-CSRF': ''})[0] == 403
    assert c.request('GET', '/api/state', headers={'Host': 'evil.example'})[0] == 403
    assert c.request('POST', '/api/analyze', {'data': 'a' * 2_000_001})[0] == 413
    assert c.request('POST', '/api/analyze', {'data': 'a' * 32_000_001, 'format': 'jsonl'})[0] == 413
    assert c.request('POST', '/api/analyze', body='{"data":1,"data":2}')[0] == 400
    assert c.request('POST', '/api/analyze', body='[' * 2000)[0] == 400
    assert c.request('POST', '/api/nope')[0] == 404
    assert c.request('OPTIONS', '/api/state')[0] == 501
    assert 'Access-Control-Allow-Origin' not in c.request('GET', '/')[2]


def test_schema_contracts_and_default_no_coverage(workspace):
    import jsonschema
    workspace.enroll('audit')
    result = attest(workspace, coverage=False)
    assert result['result']['coverage'][0]['usable_for_exact_horizon'] is False
    assert result['coverage_trust'] == 'NOT_ESTABLISHED'
    for name, value in [('workspace', workspace.public()), ('report', workspace.report(result['report_id'])['report']),
                        ('export', workspace.export(result['report_id'], consent=True))]:
        schema = json.loads((ROOT / f'schemas/customer-{name}-v1.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(value)


def test_key_symlink_hardlink_and_private_file_permissions(workspace, private_root):
    w = workspace
    w.enroll('audit')
    kid = w.state['sources']['audit']['active_key']
    path = private_root / 'workspace' / ('key-' + kid)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        w.diagnostics()
    path.chmod(0o600)
    saved = path.read_bytes()
    path.unlink()
    outside = private_root / 'unrelated-private-file'
    outside.write_bytes(saved)
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(OSError):
        w.diagnostics()
    path.unlink()
    os.link(outside, path)
    with pytest.raises(ValueError):
        w.diagnostics()
    # Validation must happen before truncation, even for a legacy staging name.
    staging = private_root / 'workspace' / 'legacy-input'
    os.link(outside, staging)
    with pytest.raises(ValueError):
        w.analyze(b'bad upload', 'jsonl')
    assert outside.read_bytes() == saved


def test_revoked_active_key_cannot_attest(workspace):
    w = workspace
    w.enroll('audit')
    kid = w.state['sources']['audit']['active_key']
    w.revoke(kid, ACK)
    with pytest.raises(ValueError, match='active key'):
        w.preview(es.canonical(fixture()), 'audit')
    assert w.diagnostics()['status'] == 'PASS'
    w.rotate('audit')
    assert attest(w)['key_provenance'].keys() != {kid}
