"""v0.5: synthetic-only quality feedback cycle; audit and rights never promoted."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import shutil
import tempfile
import unittest

from kario_pit.feedback import FeedbackFlywheel, FeedbackIntegrityError, FeedbackValidationError
from kario_pit.registry import EvidenceLedger


class FeedbackFlywheelV05Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kario_v05_")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.source_path = self.home / "source.jsonl"
        self.feedback_path = self.home / "feedback.jsonl"
        self.source = EvidenceLedger(self.source_path)
        self.private_sentinel = b"SYNTHETIC-CONTENT-MUST-NEVER-BE-STORED-IN-FEEDBACK"
        self.row = self.source.append(
            evidence_id="SYN-FB-001", provider_id="MOCK", source_record_id="RESEARCH",
            revision_id="R1", content=self.private_sentinel,
            rights_class="SYNTHETIC_PUBLIC", registered_latency_seconds=0,
            source_published_at=(datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        )
        self.decision = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        self.lab = FeedbackFlywheel(self.source_path, self.feedback_path)

    def _open(self, **changes):
        data = dict(case_id="SYN-CASE-001", evidence_id="SYN-FB-001",
                    decision_at=self.decision, issue_code="SOURCE_PROVENANCE_GAP",
                    reporter_id="reviewer_alpha")
        data.update(changes)
        return self.lab.open_case(**data)

    def _review(self, **changes):
        data = dict(case_id="SYN-CASE-001", reviewer_id="reviewer_beta", verdict="CONFIRMED")
        data.update(changes)
        return self.lab.adjudicate(**data)

    def _propose(self, **changes):
        data = dict(case_id="SYN-CASE-001", proposal_id="SYN-PROP-001",
                    candidate_policy_version="KARIO_SYNTHETIC_POLICY_CANDIDATE_V2",
                    change_code="PROVENANCE_RULE_CANDIDATE", proposer_id="reviewer_gamma")
        data.update(changes)
        return self.lab.propose_rule(**data)

    def _ready(self):
        self._open(); self._review(); self._propose()

    def test_empty_journal_safe_summary(self):
        s = self.lab.summary()
        self.assertEqual(s["case_count"], 0)
        self.assertEqual(s["production_rules_activated"], 0)

    def test_open_case_verified(self):
        item = self._open()
        self.assertEqual(item["event_type"], "CASE_OPENED")
        self.assertEqual(item["payload"]["entry_hash"], self.row["entry_hash"])
        self.assertTrue(self.lab.verify()["integrity_valid"])

    def test_open_case_keeps_source_unchanged(self):
        before = self.source_path.read_bytes()
        self._open()
        self.assertEqual(self.source_path.read_bytes(), before)

    def test_original_audit_status_unchanged_after_full_workflow(self):
        before = self.source.audit("SYN-FB-001", self.decision)
        self._ready()
        self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_delta")
        after = self.source.audit("SYN-FB-001", self.decision)
        self.assertEqual(before, after)
        self.assertIs(after["pit_certified"], False)

    def test_feedback_does_not_store_source_content(self):
        self._open()
        self.assertNotIn(self.private_sentinel, self.feedback_path.read_bytes())

    def test_output_cannot_certify_pit_time_or_rights(self):
        self._ready()
        self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_delta")
        status = self.lab.verify()
        self.assertFalse(status["pit_certified"])
        self.assertFalse(status["trusted_time_verified"])
        self.assertFalse(status["rights_legally_cleared"])
        self.assertFalse(status["rule_promoted"])
        self.assertFalse(status["model_training_performed"])

    def test_missing_source_evidence_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self._open(evidence_id="SYN-ABSENT")
        self.assertFalse(self.feedback_path.exists())

    def test_vendor_restricted_denied(self):
        self.source.append(evidence_id="SYN-LICENSED", provider_id="LITERAL_VENDOR_FIXTURE",
                           source_record_id="RESTRICTED", revision_id="R1", content=b"FAKE",
                           rights_class="VENDOR_RESTRICTED", registered_latency_seconds=0)
        with self.assertRaises(FeedbackValidationError):
            self._open(evidence_id="SYN-LICENSED")
        self.assertFalse(self.feedback_path.exists())

    def test_owned_private_denied(self):
        self.source.append(evidence_id="SYN-OWNED", provider_id="MOCK",
                           source_record_id="OWNED", revision_id="R1", content=b"FAKE",
                           rights_class="OWNED_PRIVATE", registered_latency_seconds=0)
        with self.assertRaises(FeedbackValidationError):
            self._open(evidence_id="SYN-OWNED")

    def test_unknown_issue_code_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self._open(issue_code="FREE_TEXT_UNKNOWN")

    def test_operator_free_text_id_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self._open(reporter_id="Researcher reported confidential vendor raw text")

    def test_unzoned_decision_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self._open(decision_at="2026-01-02T10:00:00")

    def test_hold_case_allowed_but_not_certified(self):
        at = (datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat()
        item = self._open(decision_at=at)
        self.assertEqual(item["payload"]["baseline_status"], "HOLD_AFTER_DECISION")
        self.assertFalse(self.lab.verify()["pit_certified"])

    def test_duplicate_case_denied(self):
        self._open()
        with self.assertRaises(FeedbackValidationError):
            self._open()

    def test_unknown_adjudication_denied(self):
        self._open()
        with self.assertRaises(FeedbackValidationError):
            self._review(verdict="PIT_CERTIFIED")

    def test_self_review_denied(self):
        self._open()
        with self.assertRaises(FeedbackValidationError):
            self._review(reviewer_id="reviewer_alpha")

    def test_unknown_case_review_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self._review()

    def test_duplicate_review_denied(self):
        self._open(); self._review()
        with self.assertRaises(FeedbackValidationError):
            self._review()

    def test_review_needs_more_evidence_is_not_candidate(self):
        self._open(); self._review(verdict="NEEDS_MORE_EVIDENCE")
        with self.assertRaises(FeedbackValidationError):
            self._propose()

    def test_rejected_case_cannot_propose(self):
        self._open(); self._review(verdict="REJECTED")
        with self.assertRaises(FeedbackValidationError):
            self._propose()

    def test_unreviewed_case_cannot_propose(self):
        self._open()
        with self.assertRaises(FeedbackValidationError):
            self._propose()

    def test_issue_change_mismatch_denied(self):
        self._open(); self._review()
        with self.assertRaises(FeedbackValidationError):
            self._propose(change_code="RIGHTS_RULE_CANDIDATE")

    def test_candidate_must_have_new_version(self):
        self._open(); self._review()
        with self.assertRaises(FeedbackValidationError):
            self._propose(candidate_policy_version="KARIO_TIME_GATE_V0.1")

    def test_duplicate_proposal_denied(self):
        self._ready()
        with self.assertRaises(FeedbackValidationError):
            self._propose()

    def test_baseline_regression_six_scenarios(self):
        self._ready()
        r = self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        self.assertEqual(r["payload"]["cases_run"], 6)
        self.assertEqual(r["payload"]["cases_passed"], 6)
        self.assertEqual(r["payload"]["scope"], "BUILTIN_BASELINE_ONLY_CANDIDATE_NOT_EVALUATED")

    def test_baseline_regression_duplicate_denied(self):
        self._ready(); self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        with self.assertRaises(FeedbackValidationError):
            self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")

    def test_regression_unknown_proposal_denied(self):
        with self.assertRaises(FeedbackValidationError):
            self.lab.run_baseline_regressions(proposal_id="SYN-UNKNOWN")

    def test_freeze_requires_regression(self):
        self._ready()
        with self.assertRaises(FeedbackValidationError):
            self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_delta")

    def test_freeze_requires_independent_approver(self):
        self._ready(); self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        for bad in ("reviewer_alpha", "reviewer_beta", "reviewer_gamma"):
            with self.subTest(reviewer=bad), self.assertRaises(FeedbackValidationError):
                self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id=bad)

    def test_candidate_freezes_not_promoted(self):
        self._ready(); self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        item = self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_delta")
        self.assertEqual(item["payload"]["state"], "FROZEN_FOR_REVIEW_NOT_PROMOTED")
        self.assertEqual(self.lab.summary()["production_rules_activated"], 0)

    def test_duplicate_freeze_denied(self):
        self._ready(); self.lab.run_baseline_regressions(proposal_id="SYN-PROP-001")
        self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_delta")
        with self.assertRaises(FeedbackValidationError):
            self.lab.freeze_candidate(proposal_id="SYN-PROP-001", approver_id="reviewer_epsilon")

    def test_metrics_are_enumerated(self):
        self._open(); self._review()
        s = self.lab.summary()
        self.assertEqual(s["issue_counts"]["SOURCE_PROVENANCE_GAP"], 1)
        self.assertEqual(s["adjudication_counts"]["CONFIRMED"], 1)
        self.assertEqual(s["training_examples_exported"], 0)

    def test_missing_source_after_open_fails_closed(self):
        self._open()
        self.source_path.unlink()
        with self.assertRaises((FeedbackValidationError, FeedbackIntegrityError)):
            self.lab.verify()

    def test_tampered_feedback_detected(self):
        self._open()
        content = self.feedback_path.read_text(encoding="utf-8")
        self.feedback_path.write_text(content.replace("SOURCE_PROVENANCE_GAP", "REVISION_LINEAGE_GAP"), encoding="utf-8")
        with self.assertRaises(FeedbackIntegrityError):
            self.lab.verify()

    def test_truncated_feedback_detected(self):
        self._open()
        with self.feedback_path.open("ab") as stream:
            stream.write(b'{"partial":')
        with self.assertRaises(FeedbackIntegrityError):
            self.lab.verify()

    def test_cannot_append_to_tampered_feedback(self):
        self._open()
        with self.feedback_path.open("ab") as stream:
            stream.write(b'{"partial":')
        with self.assertRaises(FeedbackIntegrityError):
            self._review()

    def test_incorrect_source_binding_detected(self):
        self._open()
        raw = self.source_path.read_text("utf-8")
        self.source_path.write_text(raw.replace("SYN-FB-001", "SYN-FB-002"), encoding="utf-8")
        with self.assertRaises((FeedbackValidationError, FeedbackIntegrityError)):
            self.lab.verify()

    def test_writer_lock_fails_closed(self):
        Path(str(self.feedback_path) + ".lock").write_text("lock", encoding="utf-8")
        with self.assertRaises(FeedbackIntegrityError):
            self._open()

    def test_no_network_or_vendor_import(self):
        source = Path(FeedbackFlywheel.__module__.replace(".", "/"))
        file = Path(__file__).resolve().parents[1] / "src" / "kario_pit" / "feedback" / "flywheel_v05.py"
        code = file.read_text(encoding="utf-8").lower()
        for bad in ("import lseg", "import refinitiv", "requests.get(", "urlopen(", "openai.chat", "subprocess.run("):
            self.assertNotIn(bad, code)

    def test_nonexistent_source_denied(self):
        extra = FeedbackFlywheel(self.home / "missing-source.jsonl", self.home / "fresh-feedback.jsonl")
        with self.assertRaises((FeedbackValidationError, FeedbackIntegrityError)):
            extra.open_case(case_id="SYN-C", evidence_id="SYN-FB-001", decision_at=self.decision,
                            issue_code="ATTESTATION_GAP", reporter_id="staff_A")


if __name__ == "__main__":
    unittest.main()
