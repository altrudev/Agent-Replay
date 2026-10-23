"""Offline synthetic bounded-work measurement; not a production throughput claim.

Run: PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tools/benchmark_evidence_state.py
"""
import hashlib
import time
from agent_replay.evidence_state import SCHEMA, assess_bytes, canonical, signable


def main():
    base = dict(source='audit', actor_instance_id='a', action='pay', subject='r', channel='approval')
    events = [dict(base, evidence_id=f'e-{i:04}', kind='approval', event_at=1,
                   observed_at=2, ingested_at=3,
                   scope=dict(credential='c', operation='pay', resource='r', valid_until=100))
              for i in range(512)]
    receipts = [dict(evidence_id=e['evidence_id'], source='audit', actor_instance_id='a',
                     mode='delivered', evidence_sha256=hashlib.sha256(signable('synthetic-bounded-work', 'event', e)).hexdigest(), received_at=4, observed_at=5, ingested_at=6) for e in events]
    # Exercise the global receipt/manifest cap and 512 * 1536 scope checks.
    coverage = [dict(base, channel='other', manifest_id=f'm-{i:04}', start=0, end=10,
                     observed_at=11, ingested_at=12, complete=True, evidence_ids=[])
                for i in range(1536)]
    document = dict(schema=SCHEMA, context_id='synthetic-bounded-work',
                    decision=dict(base, credential='c', at=10, since=0),
                    events=events, receipts=receipts, coverage=coverage)
    raw = canonical(document)
    results = []
    for _ in range(3):
        start = time.perf_counter()
        result = canonical(assess_bytes(raw))
        results.append(time.perf_counter() - start)
    print({'input_bytes': len(raw), 'output_bytes': len(result),
           'events': 512, 'receipts': 512, 'coverage': 1536,
           'seconds_3_runs': [round(t, 6) for t in results],
           'output_sha256': hashlib.sha256(result).hexdigest()})


if __name__ == '__main__':
    main()
