"""Negative acceptance probes for the distinct evidence-state contract."""
import copy
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_replay.evidence_state import (
    SCHEMA, MAX_BYTES, MAX_EVENTS, MAX_EDGES, assess, assess_bytes, decode,
    read_local, signable, signature, timestamp,
)

KEY = b'public-test-key-not-a-secret-00000'
ANCHORS = {'operator': {'source': 'audit', 'key': KEY}}


def fixture():
    scope = {'credential': 'c', 'operation': 'pay', 'resource': 'r', 'valid_until': 100}
    event = dict(evidence_id='e', source='audit', subject='r', actor_instance_id='a',
                 action='pay', channel='approval', kind='approval', scope=scope,
                 event_at=1, observed_at=2, ingested_at=3)
    receipt = dict(evidence_id='e', actor_instance_id='a', source='audit', mode='delivered',
                   received_at=4, observed_at=5, ingested_at=6)
    coverage = dict(manifest_id='m', source='audit', actor_instance_id='a', channel='approval',
                    action='pay', subject='r', start=0, end=10, observed_at=11,
                    ingested_at=12, complete=True, evidence_ids=['e'])
    receipt['evidence_sha256'] = hashlib.sha256(signable('case-1', 'event', event)).hexdigest()
    return dict(schema=SCHEMA, context_id='case-1', decision=dict(actor_instance_id='a',
                at=10, since=0, credential='c', action='pay', subject='r', channel='approval', source='audit'),
                events=[event], receipts=[receipt], coverage=[coverage])


def signed(doc):
    for name, kind in [('events', 'event'), ('receipts', 'receipt'), ('coverage', 'coverage')]:
        for record in doc[name]:
            if kind == 'receipt':
                event = next(e for e in doc['events'] if e['evidence_id'] == record['evidence_id'])
                record['evidence_sha256'] = hashlib.sha256(signable(doc['context_id'], 'event', event)).hexdigest()
            record['key_id'] = 'operator'
            record['signature'] = signature(doc['context_id'], kind, record, KEY)
    return doc


def run(doc, anchors=ANCHORS):
    return assess(doc, trust_anchors=anchors)


def knowledge(doc):
    return run(doc)['evidence'][0]['knowledge']


def test_authenticated_receipt_does_not_authenticate_unsigned_event():
    doc = signed(fixture())
    del doc['events'][0]['signature']
    row = run(doc)['evidence'][0]
    assert row['knowledge'] == 'KNOWN'
    assert row['authenticity'] == 'SUPPLIED_ASSERTION'
    assert run(doc)['identity'] == run(doc)['causality'] == 'NOT_ESTABLISHED'


def test_unsigned_receipt_is_only_maybe_and_missing_receipt_not_established():
    doc = fixture()
    assert knowledge(doc) == 'MAYBE_AVAILABLE'
    doc['receipts'] = []
    assert knowledge(doc) == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('field,value,expected', [
    ('actor_instance_id', 'other', 'NOT_ESTABLISHED'),
    ('received_at', 11, 'NOT_ESTABLISHED'),
    ('observed_at', 11, 'NOT_ESTABLISHED'),
    ('ingested_at', 20, 'KNOWN'),
])
def test_receipt_actor_and_three_clock_horizon(field, value, expected):
    doc = fixture()
    doc['receipts'][0][field] = value
    if field == 'received_at':
        doc['receipts'][0].update(observed_at=12, ingested_at=13)
    if field == 'observed_at':
        doc['receipts'][0]['ingested_at'] = 12
    assert knowledge(signed(doc)) == expected


@pytest.mark.parametrize('field,value', [('event_at', 11), ('observed_at', 11)])
def test_future_event_or_observation_never_prior_knowledge(field, value):
    doc = fixture()
    doc['events'][0][field] = value
    doc['events'][0]['ingested_at'] = 20
    if field == 'event_at':
        doc['events'][0]['observed_at'] = 12
        doc['receipts'][0].update(received_at=13, observed_at=14, ingested_at=15)
    assert knowledge(signed(doc)) == 'LATER_OBSERVED'


def test_late_ingestion_preserves_receipt_proven_knowledge():
    doc = fixture()
    doc['events'][0]['ingested_at'] = 50
    assert knowledge(signed(doc)) == 'KNOWN'


def empty_coverage():
    doc = fixture()
    doc['events'] = []
    doc['receipts'] = []
    doc['coverage'][0]['evidence_ids'] = []
    return doc


def test_only_exact_authenticated_complete_coverage_supports_negative():
    doc = empty_coverage()
    assert run(doc)['approval_absence'] == 'NOT_ESTABLISHED'
    assert run(signed(doc))['approval_absence'] == 'ABSENT_IN_EXACT_COVERED_SCOPE'
    assert run(doc, {})['approval_absence'] == 'NOT_ESTABLISHED'
    assert run(doc)['authority'] == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('mutation', [
    'kind', 'scope', 'event_at', 'observed_at', 'ingested_at', 'source',
    'signature_stripped', 'signature_invalid', 'key_id',
])
def test_manifest_members_require_independent_content_authentication(mutation, tmp_path):
    doc = fixture()
    # Non-approval members also need authentication before supporting absence.
    if mutation != 'kind':
        doc['events'][0]['kind'] = 'assertion'
    doc['receipts'] = []
    signed(doc)
    event = doc['events'][0]
    if mutation == 'kind':
        event['kind'] = 'assertion'
        del event['signature']
    elif mutation == 'scope':
        event['scope']['resource'] = 'tampered'
    elif mutation in ('event_at', 'observed_at', 'ingested_at'):
        event[mutation] += 1
    elif mutation == 'source':
        event['source'] = 'attacker'
    elif mutation == 'signature_stripped':
        del event['signature']
    elif mutation == 'signature_invalid':
        event['signature'] = '0' * 64
    else:
        event['key_id'] = 'untrusted'
    result = run(doc)
    assert result['evidence'][0]['authenticity'] == 'SUPPLIED_ASSERTION'
    assert result['coverage'][0]['authentication'] == 'AUTHENTICATED_COVERAGE'
    assert result['coverage'][0]['usable_for_exact_horizon'] is False
    assert result['approval_absence'] == 'NOT_ESTABLISHED'
    path = tmp_path / 'evidence.json'
    raw = json.dumps(doc).encode()
    path.write_bytes(raw)
    keypath = tmp_path / 'anchors.json'
    keypath.write_text(json.dumps({'operator': {'source': 'audit', 'key_hex': KEY.hex()}}))
    cli = subprocess.run([sys.executable, '-m', 'agent_replay.cli', 'assess-evidence',
                          str(path), '--trust-anchors', str(keypath)],
                         capture_output=True, check=True)
    assert json.loads(cli.stdout) == assess_bytes(raw, trust_anchors=ANCHORS)


@pytest.mark.parametrize('kind', ['approval', 'assertion', 'empty'])
def test_authenticated_coverage_member_controls(kind):
    doc = empty_coverage() if kind == 'empty' else fixture()
    doc['receipts'] = []
    if doc['events']:
        doc['events'][0]['kind'] = kind
    result = run(signed(doc))
    assert result['coverage'][0]['authentication'] == 'AUTHENTICATED_COVERAGE'
    assert result['coverage'][0]['usable_for_exact_horizon'] is True
    assert result['approval_absence'] == (
        'NOT_ESTABLISHED' if kind == 'approval' else 'ABSENT_IN_EXACT_COVERED_SCOPE')


@pytest.mark.parametrize('field,value', [
    ('actor_instance_id', 'other'), ('channel', 'other'), ('source', 'other'),
    ('subject', 'other'), ('action', 'other'), ('start', -1), ('end', 9),
    ('complete', False), ('evidence_ids', ['omitted']),
])
def test_authenticated_coverage_does_not_escape_exact_scope(field, value):
    doc = empty_coverage()
    doc['coverage'][0][field] = value
    assert run(signed(doc))['approval_absence'] == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('mutation', ['context', 'altered', 'wrong_key', 'wrong_source', 'missing_key'])
def test_signature_negative_mutations(mutation):
    doc = signed(empty_coverage())
    anchors = copy.deepcopy(ANCHORS)
    if mutation == 'context':
        doc['context_id'] = 'replayed-context'
    elif mutation == 'altered':
        doc['coverage'][0]['manifest_id'] = 'tampered'
    elif mutation == 'wrong_key':
        anchors['operator']['key'] = b'x' * 32
    elif mutation == 'wrong_source':
        anchors['operator']['source'] = 'attacker'
    else:
        del doc['coverage'][0]['key_id']
    result = run(doc, anchors)
    assert result['approval_absence'] == 'NOT_ESTABLISHED'
    assert result['coverage'][0]['authentication'] == 'SUPPLIED_ASSERTION'


def test_coverage_cannot_hide_supplied_counterexample_or_upgrade_verified_flag():
    doc = fixture()
    doc['coverage'][0]['evidence_ids'] = []
    assert not run(signed(doc))['coverage'][0]['usable_for_exact_horizon']
    doc['coverage'][0]['verified'] = True
    with pytest.raises(ValueError):
        run(doc)


def test_contradictory_concurrent_revocation_remains_visible_no_latest_wins():
    doc = fixture()
    revoked = copy.deepcopy(doc['events'][0])
    revoked.update(evidence_id='revoked', kind='revocation')
    doc['events'].append(revoked)
    receipt = copy.deepcopy(doc['receipts'][0])
    receipt['evidence_id'] = 'revoked'
    doc['receipts'].append(receipt)
    result = run(signed(doc))
    assert {r['kind'] for r in result['evidence']} == {'approval', 'revocation'}
    assert {r['knowledge'] for r in result['evidence']} == {'KNOWN'}
    assert result['authority'] == 'NOT_ESTABLISHED'
    assert result['causality'] == 'NOT_ESTABLISHED'
    assert all(r['receipt_provenance'] for r in result['evidence'])


@pytest.mark.parametrize('value', [1.1, True, '1', '2026-10-23T12:00:00',
    '2026-10-23 12:00:00Z', '2026-02-30T00:00:00Z', '2026-10-23T00:00:60Z',
    '2026-10-23T00:00:00-00:00', '2026-10-23T00:00:00+00:60',
    '2026-10-23T00:00:00.1234567890Z', 2**64])
def test_bogus_times_fail_closed(value):
    with pytest.raises(ValueError):
        timestamp(value)


def test_nanosecond_precision_and_offsets():
    assert timestamp('1970-01-01T00:00:00.000000001Z') == 1
    assert timestamp('1970-01-01T01:00:00.999999999+01:00') == 999999999
    assert timestamp('1969-12-31T23:59:59.999999999Z') == -1
    assert timestamp(1234567890123456789) == 1234567890123456789


def test_occurred_alias_and_invalid_clock_order():
    doc = fixture()
    event = doc['events'][0]
    event['occurred_at'] = event.pop('event_at')
    assert knowledge(signed(doc)) == 'KNOWN'
    event['observed_at'] = 0
    with pytest.raises(ValueError):
        run(doc)


@pytest.mark.parametrize('raw', [b'{"schema":1,"schema":2}', b'{"a":{"x":1,"x":2}}',
    b'{"x":NaN}', b'[' * 20 + b']' * 20, b' ' * (MAX_BYTES + 1)])
def test_hostile_json(raw):
    with pytest.raises(ValueError):
        decode(raw)


@pytest.mark.parametrize('field', ['parent_ids', 'intent', 'verified', 'policy', 'extensions'])
def test_unknown_critical_semantics_rejected(field):
    doc = fixture()
    doc['events'][0][field] = []
    with pytest.raises(ValueError):
        run(doc)


def test_graph_and_event_budgets():
    doc = fixture()
    doc['events'] *= MAX_EVENTS + 1
    with pytest.raises(ValueError, match='budget'):
        run(doc)
    doc = fixture()
    doc['receipts'] *= MAX_EDGES + 1
    with pytest.raises(ValueError, match='budget'):
        run(doc)


def test_symlinks_directories_and_oversize_files_rejected(tmp_path):
    path = tmp_path / 'input'
    path.write_text('{}')
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(OSError):
        read_local(link)
    directory_link = tmp_path / 'dir'
    directory_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        read_local(directory_link / 'input')
    with pytest.raises(ValueError):
        read_local(tmp_path)
    with pytest.raises(ValueError):
        read_local(path, 1)


def test_parallel_assessments_deterministic_and_no_mutation():
    doc = signed(fixture())
    before = copy.deepcopy(doc)
    with ThreadPoolExecutor(max_workers=4) as pool:
        outputs = list(pool.map(lambda _: run(doc), range(16)))
    assert all(x == outputs[0] for x in outputs)
    assert doc == before


def test_independent_cli_api_equivalence_and_default_disclosure(tmp_path):
    doc = signed(fixture())
    raw = json.dumps(doc).encode()
    path = tmp_path / 'evidence.json'
    path.write_bytes(raw)
    keypath = tmp_path / 'operator.json'
    keypath.write_text(json.dumps({'operator': {'source': 'audit', 'key_hex': KEY.hex()}}))
    cli = subprocess.run([sys.executable, '-m', 'agent_replay.cli', 'assess-evidence',
                          str(path), '--trust-anchors', str(keypath)],
                         capture_output=True, check=True, env=os.environ)
    assert json.loads(cli.stdout) == assess_bytes(raw, trust_anchors=ANCHORS)
    assert KEY.hex().encode() not in cli.stdout
    assert b'"evidence_id"' not in cli.stdout
    assert b'"credential"' not in cli.stdout
    assert b'case-1' not in cli.stdout


def test_incident_v2_is_not_accepted_or_changed():
    from agent_replay.reconstruct import reconstruct
    incident = reconstruct('examples/refund-750/events.jsonl')
    assert incident['schema'] == 'agent-replay.incident.v2'
    with pytest.raises(ValueError):
        run(incident)


@pytest.mark.parametrize('field,value,expected', [
    ('credential', 'wrong', 'OUT_OF_SCOPE'),
    ('operation', 'wrong', 'OUT_OF_SCOPE'),
    ('resource', 'wrong', 'OUT_OF_SCOPE'),
    ('valid_until', 9, 'EXPIRED_APPROVAL'),
    ('valid_until', 100, 'APPROVAL_EVIDENCED_FRESHNESS_NOT_ESTABLISHED'),
])
def test_authority_scope_and_expiry(field, value, expected):
    doc = fixture()
    doc['events'][0]['scope'][field] = value
    assert run(signed(doc))['evidence'][0]['authority_evidence'] == expected


def test_authenticated_revocation_blocks_approval_precedence():
    doc = fixture()
    event = copy.deepcopy(doc['events'][0])
    event.update(evidence_id='rev', kind='revocation')
    doc['events'].append(event)
    receipt = copy.deepcopy(doc['receipts'][0])
    receipt['evidence_id'] = 'rev'
    doc['receipts'].append(receipt)
    roles = {r['authority_evidence'] for r in run(signed(doc))['evidence']}
    assert roles == {'REVOCATION_EVIDENCED', 'CONFLICTING_REVOCATION'}


def test_schemas_and_authoritative_manifest():
    from pathlib import Path
    import jsonschema
    for suffix, instance in [('input', signed(fixture())), ('output', run(signed(fixture())))]:
        schema = json.loads(Path(f'schemas/evidence-state-v1.{suffix}.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(instance, schema)
    manifest = json.loads(Path('schemas/authoritative-fields-v1.json').read_text())
    assert set(run(signed(fixture()))).issubset(manifest['evidence-state-v1'])


def test_duplicate_key_error_does_not_disclose_raw_key():
    with pytest.raises(ValueError) as error:
        decode(b'{"sensitive-raw-key":1,"sensitive-raw-key":2}')
    assert 'sensitive-raw-key' not in str(error.value)


def test_no_chronology_only_actor_knowledge_without_receipt():
    doc = signed(fixture())
    doc['receipts'] = []
    row = run(doc)['evidence'][0]
    assert row['knowledge'] == 'NOT_ESTABLISHED'
    assert row['authority_evidence'] == 'NOT_ESTABLISHED'


def test_complete_coverage_never_creates_knowledge():
    doc = fixture()
    doc['receipts'] = []
    result = run(signed(doc))
    assert result['coverage'][0]['usable_for_exact_horizon']
    assert result['evidence'][0]['knowledge'] == 'NOT_ESTABLISHED'


def test_order_of_concurrent_records_does_not_change_findings():
    doc = fixture()
    second = copy.deepcopy(doc['events'][0])
    second.update(evidence_id='second', kind='revocation')
    doc['events'].append(second)
    doc = signed(doc)
    before = run(doc)
    doc['events'].reverse()
    after = run(doc)
    # Canonical input integrity includes array order; findings do not infer order.
    assert before.pop('canonical_sha256') != after.pop('canonical_sha256')
    assert before == after


def test_evidence_state_cannot_silently_use_legacy_share_format():
    from agent_replay.share import build_share_bundle
    with pytest.raises(ValueError, match='unsupported incident schema'):
        build_share_bundle(run(fixture()))


@pytest.mark.parametrize('missing', ['source', 'observed_at', 'ingested_at', 'manifest_id'])
def test_missing_coverage_provenance_fails_closed(missing):
    doc = signed(empty_coverage())
    del doc['coverage'][0][missing]
    with pytest.raises(ValueError):
        run(doc)


def test_signature_domain_separation_and_consultation():
    doc = fixture()
    doc['receipts'][0]['mode'] = 'consulted'
    doc = signed(doc)
    assert knowledge(doc) == 'KNOWN'
    record = doc['coverage'][0]
    record['signature'] = signature(doc['context_id'], 'event', record, KEY)
    assert run(doc)['coverage'][0]['authentication'] == 'SUPPLIED_ASSERTION'


def test_unreceived_revocation_cannot_be_retrospective_actor_knowledge():
    doc = fixture()
    revocation = copy.deepcopy(doc['events'][0])
    revocation.update(evidence_id='rev', kind='revocation')
    doc['events'].append(revocation)
    rows = run(signed(doc))['evidence']
    assert {r['authority_evidence'] for r in rows} == {
        'APPROVAL_EVIDENCED_FRESHNESS_NOT_ESTABLISHED', 'NOT_ESTABLISHED'}


def test_sensitive_identifiers_and_signatures_are_not_rendered():
    doc = fixture()
    doc['events'][0]['evidence_id'] = 'sensitive-evidence-id'
    doc['receipts'][0]['evidence_id'] = 'sensitive-evidence-id'
    doc['coverage'][0]['evidence_ids'] = ['sensitive-evidence-id']
    doc = signed(doc)
    output = json.dumps(run(doc))
    assert 'sensitive-evidence-id' not in output
    assert all(r['signature'] not in output for r in doc['events'] + doc['receipts'] + doc['coverage'])


def test_authenticated_receipt_cannot_be_rebound_to_altered_event_content():
    doc = signed(fixture())
    # Even stripping event authentication cannot reuse a receipt for new content.
    doc['events'][0].pop('signature')
    doc['events'][0]['scope']['resource'] = 'attacker-resource'
    with pytest.raises(ValueError, match='content binding'):
        run(doc)


def test_output_budget_fails_without_partial_verdict(monkeypatch):
    import agent_replay.evidence_state as engine
    monkeypatch.setattr(engine, 'MAX_OUTPUT', 100)
    with pytest.raises(ValueError, match='output budget'):
        run(fixture())
