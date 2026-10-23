import hashlib
import json
import subprocess
import sys

import pytest

from agent_replay.normalize import EvidenceFormatError
from agent_replay.reconstruct import reconstruct, reconstruct_records
from agent_replay.reproduce import compare_reconstruction
from agent_replay.report import render_text
from agent_replay.share import sanitize_incident
from agent_replay import strict_json


def event(name, parents=(), **changes):
    return dict(event_id=name, timestamp="2026-01-01T00:00:00Z", kind="test",
                actor="claimed", expected={"x": True}, observed={"x": False},
                parent_ids=list(parents), **changes)


def report(records):
    return reconstruct_records(records, input_sha256="a" * 64)


def test_four_states_and_null(tmp_path):
    e = event("a")
    e.update(expected={"missing": None, "null": None, "false": False, "bad": True},
             observed={"null": None, "false": False, "bad": None, "extra": 1})
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(e) + "\n")
    r = reconstruct(path)
    assert r['timeline'][0]['status'] == 'INCOMPLETE'
    assert {c['field']: c['status'] for c in r['timeline'][0]['comparisons']} == {
        'missing': 'NOT_OBSERVED', 'null': 'MATCH', 'false': 'MATCH',
        'bad': 'MISMATCH', 'extra': 'NOT_COMPARABLE'}
    assert [m['field'] for m in r['divergences'][0]['mismatches']] == ['bad']
    assert r['evidence_completeness'] == 'INCOMPLETE'
    public = sanitize_incident(r)
    assert {c['status'] for c in public['timeline'][0]['comparisons']} == {
        'MATCH', 'MISMATCH', 'NOT_OBSERVED', 'NOT_COMPARABLE'}


def test_missing_is_neither_valid_nor_divergent():
    e = event('a'); e['observed'] = {}
    r = report([e])
    assert r['timeline'][0]['status'] == 'INCOMPLETE'
    assert r['divergences'] == []


def test_independent_frontier_and_causal_equal_time():
    r = report([event('b'), event('a')])
    assert r['first_provable_divergence'] is None
    assert r['first_divergence_order'] == 'AMBIGUOUS'
    assert [d['event_id'] for d in r['first_provable_divergence_set']] == ['a', 'b']
    assert all(c['relationship'] == 'ROOT_DIVERGENCE' for c in r['causal_chain'])
    assert 'order not established' in render_text(r)
    assert 'No provable divergence found' not in render_text(r)
    assert len(sanitize_incident(r)['first_provable_divergence_set']) == 2
    connected = report([event('a', ['z']), event('z')])
    assert connected['first_provable_divergence']['event_id'] == 'z'
    assert connected['causal_chain'][1]['relationship'] == 'EXPLICITLY_DOWNSTREAM'


def test_permuted_lines_identity(tmp_path):
    path = tmp_path / 'events.jsonl'
    lines = [json.dumps(event('b')), json.dumps(event('a'))]
    path.write_text('\n'.join(lines) + '\n'); first = reconstruct(path)
    path.write_text('\n'.join(reversed(lines)) + '\n'); second = reconstruct(path)
    comparison = compare_reconstruction(first, second)
    assert comparison['status'] == 'REPRODUCED'
    assert comparison['checks']['canonical_sha256']
    assert not comparison['checks']['exact_input_sha256']


@pytest.mark.parametrize('bad', ['{"x":1,"x":2}', '{"a":{"x":1,"x":2}}',
                                    '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'])
def test_strict_json_ingestion(bad, tmp_path):
    with pytest.raises(ValueError): strict_json.loads(bad)
    path = tmp_path / 'bad.jsonl'; path.write_text(bad + '\n')
    with pytest.raises(EvidenceFormatError): reconstruct(path)
    for fmt in ('aps', 'otel'):
        proc = subprocess.run([sys.executable, '-m', 'agent_replay.cli', 'reconstruct',
                               str(path), '--format', fmt, '--json'], capture_output=True, text=True)
        assert proc.returncode != 0
        assert not proc.stdout


@pytest.mark.parametrize('value', [float('nan'), float('inf')])
def test_nonfinite_programmatic_and_output(value):
    with pytest.raises(ValueError): strict_json.dumps({'value': value})
    e = event('a'); e['observed']['x'] = value
    with pytest.raises(EvidenceFormatError): report([e])


def test_large_chain_bounded_output():
    r = report([event(str(i), [str(i-1)] if i else []) for i in range(1100)])
    assert r['causal_ancestor_output_scope'] == 'TRUNCATED'
    last = r['causal_chain'][-1]
    assert last['divergent_ancestor_count'] == 1099
    assert last['ancestors_truncated']
    assert len(last['divergent_ancestor_ids']) == last['ancestor_output_limit'] == 128
    assert sanitize_incident(r)['causal_ancestor_output_scope'] == 'TRUNCATED'


def test_ddc_pin_fail_closed(tmp_path, monkeypatch):
    from agent_replay_ddc.radial_runner import _load_radial_module, RadialAdapterError
    source = tmp_path / 'src'; source.mkdir()
    module = source / 'radial_frequency_v10.py'
    module.write_text('raise RuntimeError("must never execute")')
    tmp_path.chmod(0o700); source.chmod(0o700); module.chmod(0o600)
    monkeypatch.setenv('DDC_RADIAL_ROOT', str(tmp_path))
    monkeypatch.delenv('DDC_RADIAL_SHA256', raising=False)
    with pytest.raises(RadialAdapterError, match='operator-supplied'): _load_radial_module()
    monkeypatch.setenv('DDC_RADIAL_SHA256', '0'*64)
    with pytest.raises(RadialAdapterError, match='does not match'): _load_radial_module()
    module.write_text('PINNED = True\n')
    monkeypatch.setenv('DDC_RADIAL_SHA256', hashlib.sha256(module.read_bytes()).hexdigest())
    assert _load_radial_module()[0].PINNED
    module.chmod(0o666)
    with pytest.raises(RadialAdapterError, match='permission'): _load_radial_module()


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '1.2', float('inf'), True])
def test_otlp_double_rejects_permissive_coercion(value):
    from agent_replay.otel import _otel_value, OpenTelemetryFormatError
    with pytest.raises(OpenTelemetryFormatError):
        _otel_value({'doubleValue': value})


def test_frontier_through_nondivergent_parent():
    middle = event('middle', ['z']); middle['observed'] = {'x': True}
    r = report([event('a', ['middle']), middle, event('z')])
    assert [d['event_id'] for d in r['first_provable_divergence_set']] == ['z']
    assert r['causal_chain'][-1]['relationship'] == 'EXPLICITLY_DOWNSTREAM'
