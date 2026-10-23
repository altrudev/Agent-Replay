#!/usr/bin/env python3
"""Offline synthetic fresh-workspace demo; no credentials or remote services."""
import argparse
import json
from pathlib import Path
from agent_replay.customer import Workspace
from agent_replay.evidence_state import canonical, SCHEMA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True)
    args = parser.parse_args()
    if Path(args.workspace).exists():
        parser.error('Choose a new directory; the demo never modifies an existing workspace')
    document = {'schema': SCHEMA, 'context_id': 'synthetic-demo',
        'decision': {'actor_instance_id': 'demo-agent', 'at': 10, 'since': 0,
                     'credential': 'demo-credential', 'action': 'pay', 'subject': 'demo-resource',
                     'channel': 'approval', 'source': 'demo-audit'},
        'events': [], 'receipts': [], 'coverage': [{'manifest_id': 'demo-manifest',
            'source': 'demo-audit', 'actor_instance_id': 'demo-agent', 'channel': 'approval',
            'action': 'pay', 'subject': 'demo-resource', 'start': 0, 'end': 10,
            'observed_at': 11, 'ingested_at': 12, 'complete': True, 'evidence_ids': []}]}
    raw = canonical(document)
    with Workspace(args.workspace, create=True) as w:
        w.enroll('demo-audit')
        supplied = w.analyze(raw)
        assert supplied['result']['approval_absence'] == 'NOT_ESTABLISHED'
        review = w.preview(raw, 'demo-audit', coverage=True)
        # This is a synthetic self-owned fixture. The dashboard asks the customer
        # to review and acknowledge the equivalent exact context and record list.
        signed = w.analyze(raw, review=review, confirmation=review['confirmation'], own=True)
        assert signed['result']['approval_absence'] == 'ABSENT_IN_EXACT_COVERED_SCOPE'
        assert w.verify(signed['report_id'])['status'] == 'REPRODUCED'
        w.rotate('demo-audit')
        assert w.verify(signed['report_id'], historical=True)['status'] == 'REPRODUCED'
        assert w.diagnostics()['status'] == 'PASS'
        print(json.dumps({'supplied_absence': supplied['result']['approval_absence'],
                          'customer_attested_absence': signed['result']['approval_absence'],
                          'historical_verification': 'REPRODUCED',
                          'export': w.export(signed['report_id'], consent=True)}, indent=2))


if __name__ == '__main__':
    main()
