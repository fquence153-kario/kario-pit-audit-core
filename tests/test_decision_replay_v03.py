"""Entire suite is synthetic. Mocked timestamps are ONLY for unit tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import unittest

from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer


class DecisionReplayV03Tests(unittest.TestCase):
    T1 = "2026-01-02T10:00:00Z"
    T2 = "2026-01-02T10:01:00Z"
    T3 = "2026-01-02T10:02:00Z"

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "synthetic" / "ledger.jsonl"
        self.ledger = EvidenceLedger(self.path)
        self.replayer = DecisionReplayer(self.path)

    def add(self, at, **changes):
        record = dict(
            evidence_id="SYN-R1", provider_id="MOCK",
            source_record_id="DOC", revision_id="R1",
            content=b"SYNTHETIC_REVISION_ONE",
            registered_latency_seconds=30,
            source_published_at="2026-01-02T09:59:00Z",
            rights_class="SYNTHETIC_PUBLIC",
        )
        record.update(changes)
        # A controlled clock is permitted ONLY in synthetic unit tests.
        with patch("kario_pit.registry.ledger._utc_now", return_value=at):
            return self.ledger.append(**record)

    def add_pair(self, *, second_latency=30, second_rights="SYNTHETIC_PUBLIC"):
        self.add(self.T1)
        self.add(
            self.T2, evidence_id="SYN-R2", revision_id="R2",
            supersedes_evidence_id="SYN-R1",
            source_published_at="2026-01-02T10:00:45Z",
            content=b"SYNTHETIC_REVISION_TWO",
            rights_class=second_rights,
            registered_latency_seconds=second_latency,
        )

    def replay(self, decision, **changes):
        args = dict(
            provider_id="MOCK", source_record_id="DOC", decision_at=decision
        )
        args.update(changes)
        return self.replayer.replay_document(**args)

    def test_missing_ledger_is_hold(self):
        r = self.replay("2026-01-02T10:00:30Z")
        self.assertEqual(r["status"], "HOLD_LEDGER_MISSING")
        self.assertFalse(r["registry_integrity_verified"])

    def test_missing_source_is_hold(self):
        self.add(self.T1)
        r = self.replay("2026-01-02T10:00:30Z", source_record_id="OTHER")
        self.assertEqual(r["status"], "HOLD_SOURCE_NOT_FOUND")

    def test_before_receipt_is_hold(self):
        self.add(self.T1)
        self.assertEqual(
            self.replay("2026-01-02T09:59:59Z")["status"],
            "HOLD_NO_VERSION_AT_DECISION",
        )

    def test_one_second_before_boundary_is_hold(self):
        self.add(self.T1)
        self.assertEqual(
            self.replay("2026-01-02T10:00:29Z")["status"],
            "HOLD_NO_VERSION_AT_DECISION",
        )

    def test_boundary_selects_first_but_never_certifies(self):
        self.add(self.T1)
        r = self.replay("2026-01-02T10:00:30Z")
        self.assertEqual(r["status"], "TIME_GATE_PASS_UNVERIFIED")
        self.assertEqual(r["selected_revision_id"], "R1")
        self.assertTrue(r["time_gate_pass"])
        self.assertFalse(r["pit_certified"])
        self.assertTrue(r["registry_integrity_verified"])
        self.assertEqual(r["selected_available_at_utc"], "2026-01-02T10:00:30Z")

    def test_future_revision_not_selected_in_past(self):
        self.add_pair()
        r = self.replay("2026-01-02T10:00:30Z")
        self.assertEqual(r["selected_evidence_id"], "SYN-R1")
        self.assertEqual(r["selected_revision_id"], "R1")
        self.assertNotIn("SYN-R2", json.dumps(r))
        self.assertNotIn('"R2"', json.dumps(r))
        self.assertNotIn("entry_count", r)
        self.assertNotIn("head_hash", r)

    def test_observed_but_not_effective_revision_not_selected(self):
        self.add_pair()
        r = self.replay("2026-01-02T10:01:29Z")
        self.assertEqual(r["selected_revision_id"], "R1")

    def test_new_revision_selected_at_boundary(self):
        self.add_pair()
        r = self.replay("2026-01-02T10:01:30Z")
        self.assertEqual(r["selected_revision_id"], "R2")
        self.assertEqual(r["selected_available_at_utc"], "2026-01-02T10:01:30Z")

    def test_late_revision_respects_own_latency(self):
        self.add_pair(second_latency=120)
        self.assertEqual(
            self.replay("2026-01-02T10:01:30Z")["selected_revision_id"], "R1"
        )
        self.assertEqual(
            self.replay("2026-01-02T10:03:00Z")["selected_revision_id"], "R2"
        )

    def test_other_document_interleave_does_not_replace(self):
        self.add(self.T1)
        self.add("2026-01-02T10:00:45Z", evidence_id="SYN-OTHER",
                 source_record_id="OTHER")
        self.add(self.T2, evidence_id="SYN-R2", revision_id="R2",
                 supersedes_evidence_id="SYN-R1",
                 source_published_at="2026-01-02T10:00:46Z")
        self.assertEqual(
            self.replay("2026-01-02T10:01:30Z")["selected_revision_id"], "R2"
        )

    def test_rights_restricted_record_is_hold(self):
        self.add(self.T1, rights_class="VENDOR_RESTRICTED")
        r = self.replay("2026-01-02T10:00:30Z")
        self.assertEqual(r["status"], "HOLD_RIGHTS_POLICY")
        self.assertIsNone(r["selected_evidence_id"])
        self.assertNotIn("content_sha256", json.dumps(r))

    def test_future_rights_do_not_change_past_snapshot(self):
        self.add_pair(second_rights="VENDOR_RESTRICTED")
        self.assertEqual(
            self.replay("2026-01-02T10:00:30Z")["selected_revision_id"], "R1"
        )
        self.assertEqual(
            self.replay("2026-01-02T10:01:01Z")["status"], "HOLD_RIGHTS_POLICY"
        )

    def test_missing_source_timestamp_is_hold(self):
        self.add(self.T1, source_published_at=None)
        self.assertEqual(
            self.replay("2026-01-02T10:00:30Z")["status"],
            "HOLD_SOURCE_TIME_MISSING",
        )

    def test_chronology_conflict_is_hold(self):
        self.add(self.T1, source_published_at="2026-01-02T10:00:01Z")
        self.assertEqual(
            self.replay("2026-01-02T10:00:30Z")["status"],
            "HOLD_CHRONOLOGY_CONFLICT",
        )

    def test_clock_regression_is_hold(self):
        self.add(self.T2)
        self.add(self.T1, source_record_id="OTHER", evidence_id="SYN-OTHER")
        r = self.replay("2026-01-02T10:01:30Z")
        self.assertEqual(r["status"], "HOLD_LEDGER_CLOCK_REGRESSION")
        self.assertFalse(r["registry_integrity_verified"])

    def test_hash_chain_tamper_is_hold(self):
        self.add(self.T1)
        raw = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            raw.replace('"revision_id":"R1"', '"revision_id":"RX"'),
            encoding="utf-8", newline="\n",
        )
        self.assertEqual(
            self.replay("2026-01-02T10:00:30Z")["status"],
            "HOLD_LEDGER_INTEGRITY",
        )

    def test_invalid_naive_decision_is_hold(self):
        self.add(self.T1)
        self.assertEqual(
            self.replay("2026-01-02T10:00:30")["status"],
            "HOLD_INVALID_DECISION_AT",
        )

    def test_invalid_source_identifier_is_hold(self):
        self.add(self.T1)
        self.assertEqual(
            self.replay("2026-01-02T10:00:30Z", source_record_id="../../X")["status"],
            "HOLD_INVALID_QUERY",
        )

    def test_replay_does_not_write_ledger(self):
        self.add_pair()
        before = self.path.read_bytes()
        self.replay("2026-01-02T10:01:30Z")
        self.assertEqual(self.path.read_bytes(), before)

    def test_timezone_offset_decision_matches_utc(self):
        self.add(self.T1)
        r = self.replay("2026-01-02T21:00:30+11:00")
        self.assertEqual(r["decision_at_utc"], "2026-01-02T10:00:30Z")
        self.assertEqual(r["selected_revision_id"], "R1")


if __name__ == "__main__":
    unittest.main()
