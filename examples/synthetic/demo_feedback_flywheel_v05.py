"""End-to-end synthetic audit feedback loop. No vendor data or LSEG calls."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kario_pit.registry import EvidenceLedger
from kario_pit.feedback import FeedbackFlywheel


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--feedback", type=Path, required=True)
    args = parser.parse_args()

    if args.ledger.exists() or args.feedback.exists():
        parser.error("Refuse to overwrite an existing demo artifact")
    if args.ledger.resolve() == args.feedback.resolve():
        parser.error("Source and feedback journal must be different files")

    source = EvidenceLedger(args.ledger)
    source_row = source.append(
        evidence_id="SYN-FEEDBACK-DEMO", provider_id="MOCK", source_record_id="DEMO-ONLY",
        revision_id="R1", rights_class="SYNTHETIC_PUBLIC", registered_latency_seconds=0,
        source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=2)).isoformat(),
        content=b"SYNTHETIC PUBLIC TIME-LIMITED EVIDENCE METADATA DEMO ONLY",
    )
    decision = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    before = source.audit("SYN-FEEDBACK-DEMO", decision)
    baseline_sha256 = args.ledger.read_bytes()
    feedback = FeedbackFlywheel(args.ledger, args.feedback)

    feedback.open_case(case_id="SYN-CASE-001", evidence_id="SYN-FEEDBACK-DEMO",
        decision_at=decision, issue_code="SOURCE_PROVENANCE_GAP", reporter_id="operator_A")
    feedback.adjudicate(case_id="SYN-CASE-001", reviewer_id="reviewer_B", verdict="CONFIRMED")
    feedback.propose_rule(case_id="SYN-CASE-001", proposal_id="SYN-PROPOSAL-001",
        candidate_policy_version="KARIO_SYNTHETIC_PROVENANCE_POLICY_V2_CANDIDATE",
        change_code="PROVENANCE_RULE_CANDIDATE", proposer_id="engineer_C")
    regression = feedback.run_baseline_regressions(proposal_id="SYN-PROPOSAL-001")
    frozen = feedback.freeze_candidate(proposal_id="SYN-PROPOSAL-001", approver_id="governor_D")

    after = source.audit("SYN-FEEDBACK-DEMO", decision)
    report = {
        "source_ledger": str(args.ledger), "feedback_ledger": str(args.feedback),
        "source_integrity": source.verify(), "feedback_integrity": feedback.verify(),
        "source_ledger_unchanged": args.ledger.read_bytes() == baseline_sha256,
        "original_audit_unchanged": before == after,
        "source_entry_hash": source_row["entry_hash"],
        "original_status": before["status"],
        "regression_scope": regression["payload"]["scope"],
        "candidate_state": frozen["payload"]["state"],
        "feedback_summary": feedback.summary(),
        "notice": "Synthetic only. Candidate is frozen for review, NOT implemented, evaluated or promoted. No PIT, legal rights or trusted-time certification.",
    }
    assert report["source_ledger_unchanged"] and report["original_audit_unchanged"]
    assert report["feedback_integrity"]["entry_count"] == 5
    assert report["feedback_summary"]["production_rules_activated"] == 0
    assert report["feedback_integrity"]["pit_certified"] is False
    assert report["feedback_integrity"]["trusted_time_verified"] is False
    assert report["feedback_integrity"]["rights_legally_cleared"] is False
    print(json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
