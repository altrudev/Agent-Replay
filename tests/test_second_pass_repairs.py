from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import types

import jsonschema
import pytest

from agent_replay.reconstruct import reconstruct
from agent_replay.reproduce import compare_reconstruction
from agent_replay.share import build_share_bundle

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/legacy-v06'


def legacy_pair():
    return json.loads((FIXTURE / 'incident.json').read_text()), reconstruct(FIXTURE / 'events.jsonl')


def test_actual_v06_incident_has_unknown_current_scope():
    old, current = legacy_pair()
    assert old['canonical_sha256'] == current['canonical_sha256']
    result = compare_reconstruction(old, current)
    assert result['status'] == 'INCOMPLETE'
    assert result['core_reproduced'] is False
    assert result['differences'] == []
    assert result['checks']['first_provable_divergence_set'] is None
    assert result['checks']['causal_chain_ancestor_metadata'] is None
    assert 'PARTIAL' in result['identity_scope']
    assert set(result['unavailable_checks']) == {'first_provable_divergence_set', 'causal_chain_ancestor_metadata'}
    assert compare_reconstruction(current, deepcopy(current))['status'] == 'REPRODUCED'


@pytest.mark.parametrize('change', ['canonical', 'ancestor', 'first', 'frontier', 'count'])
def test_known_drift_survives_legacy_compatibility(change):
    old, current = legacy_pair()
    if change == 'canonical': current['canonical_sha256'] = '0' * 64
    if change == 'ancestor': current['causal_chain'][-1]['divergent_ancestor_ids'] = []
    if change == 'first': current['first_provable_divergence']['event_id'] = 'different'
    if change == 'frontier':
        old = deepcopy(current)
        current['first_provable_divergence_set'] = []
    if change == 'count':
        old = deepcopy(current)
        current['causal_chain'][-1]['divergent_ancestor_count'] += 1
    assert compare_reconstruction(old, current)['status'] == 'DRIFTED'


def test_actual_v06_public_share_valid_and_redacted():
    old, _ = legacy_pair()
    public = build_share_bundle(old)['incident']
    jsonschema.Draft202012Validator(json.loads((ROOT / 'schemas/public-share-v1.schema.json').read_text())).validate(public)
    for key in ('first_divergence_order', 'causal_ancestor_output_scope', 'first_provable_divergence_set'):
        assert key not in public
    assert 'private-' not in json.dumps(public)


@pytest.mark.parametrize('prior_present', [False, True])
def test_pinned_execution_failure_restores_import_state(tmp_path, monkeypatch, prior_present):
    from agent_replay_ddc.radial_runner import _load_radial_module
    src = tmp_path / 'src'
    src.mkdir(mode=0o700)
    tmp_path.chmod(0o700)
    module = src / 'radial_frequency_v10.py'
    module.write_text('PARTIAL = True\nraise RuntimeError("execution failed")\n')
    module.chmod(0o600)
    monkeypatch.setenv('DDC_RADIAL_ROOT', str(tmp_path))
    monkeypatch.setenv('DDC_RADIAL_SHA256', hashlib.sha256(module.read_bytes()).hexdigest())
    name = 'agent_replay_ddc_radial_frequency_v10'
    prior = types.ModuleType(name)
    if prior_present: monkeypatch.setitem(sys.modules, name, prior)
    else: monkeypatch.delitem(sys.modules, name, raising=False)
    before_path = sys.path[:]
    with pytest.raises(RuntimeError, match='execution failed'):
        _load_radial_module()
    assert sys.path == before_path
    assert (sys.modules.get(name) is prior) if prior_present else name not in sys.modules
