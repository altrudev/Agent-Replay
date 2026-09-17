from agent_replay.reconstruct import reconstruct
from agent_replay_ddc.render import render_radial


def test_concise_radial_report_resolves_subject_labels():
    incident = reconstruct("examples/refund-750/events.jsonl")
    radial = {
        "engine": "ddc-radial-frequency/1.0",
        "authoritative": False,
        "disposition": "CANDIDATE_FINDINGS",
        "examined_nodes": 5,
        "examined_edges": 3,
        "hypotheses": [
            {
                "prior_id": "unsafe-retry",
                "title": "Unsafe retry / duplicate effect",
                "score": 0.985,
                "subjects": ["evt_024", "evt_025"],
                "rationale": "An ambiguous result can turn a retry into a second side effect.",
                "falsification_test": "Commit the effect, suppress acknowledgement, and retry.",
            }
        ],
    }

    text = render_radial(incident, radial)

    assert "DDC RADIAL REVIEW" in text
    assert "Candidates: 1 | Prior classes: 1" in text
    assert "approval.check (evt_024)" in text
    assert "payment.refund (evt_025)" in text
    assert "Score: 0.985" in text
    assert "Matching edges: 1" in text
    assert "non-authoritative CANDIDATE" in text


def test_concise_radial_report_groups_same_prior_without_losing_raw_count():
    incident = reconstruct("examples/refund-750/events.jsonl")
    radial = {
        "engine": "ddc-radial-frequency/1.0",
        "authoritative": False,
        "disposition": "CANDIDATE_FINDINGS",
        "examined_nodes": 5,
        "examined_edges": 3,
        "hypotheses": [
            {
                "prior_id": "toctou",
                "title": "Check/use temporal race",
                "score": 0.85,
                "subjects": ["evt_019", "evt_024"],
                "rationale": "r",
                "falsification_test": "f",
            },
            {
                "prior_id": "toctou",
                "title": "Check/use temporal race",
                "score": 0.85,
                "subjects": ["evt_024", "evt_025"],
                "rationale": "r",
                "falsification_test": "f",
            },
        ],
    }

    text = render_radial(incident, radial)

    assert "Candidates: 2 | Prior classes: 1" in text
    assert text.count("Prior: toctou") == 1
    assert "Matching edges: 2" in text
    assert "--json preserves the complete per-edge hypothesis set" in text


def test_concise_radial_report_honors_limit_by_prior_class():
    incident = reconstruct("examples/refund-750/events.jsonl")
    radial = {
        "engine": "ddc-radial-frequency/1.0",
        "authoritative": False,
        "disposition": "CANDIDATE_FINDINGS",
        "examined_nodes": 5,
        "examined_edges": 3,
        "hypotheses": [
            {
                "prior_id": f"p{i}",
                "title": f"Candidate {i}",
                "score": 0.9,
                "subjects": ["evt_019"],
                "rationale": "r",
                "falsification_test": "f",
            }
            for i in range(3)
        ],
    }

    text = render_radial(incident, radial, limit=2)

    assert "Candidate 0" in text
    assert "Candidate 1" in text
    assert "Candidate 2" not in text
    assert "1 additional prior classes omitted" in text
