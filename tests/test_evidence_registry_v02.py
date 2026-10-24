"""All test values are synthetic. No external accounts, API calls or SDKs."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from kario_pit.registry import (
    EvidenceLedger, LedgerIntegrityError, RegistryValidationError,
    DuplicateEvidenceError,
)


class EvidenceRegistryV02Tests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic" / "registry.jsonl"
        self.registry = EvidenceLedger(self.path)

    def add(self, **changes):
        data = dict(
            evidence_id="SYN-E1", provider_id="MOCK", source_record_id="DOC1",
            revision_id="R1", content=b"SYNTHETIC_EVENT_SNAPSHOT_ONLY",
            registered_latency_seconds=30,
            rights_class="SYNTHETIC_PUBLIC",
            source_published_at="2026-01-02T10:00:00Z",
        )
        data.update(changes)
        return self.registry.append(**data)

    @staticmethod
    def at_delay(entry, delta):
        receipt = datetime.fromisoformat(
            entry["recorded_at_utc"].replace("Z", "+00:00")
        )
        return (receipt + timedelta(seconds=delta)).isoformat()

    def test_append_and_verify_chain(self):
        first = self.add()
        result = self.registry.verify()
        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(result["head_hash"], first["entry_hash"])
        self.assertTrue(result["integrity_valid"])

    def test_no_content_bytes_in_ledger(self):
        self.add()
        self.assertNotIn(b"SYNTHETIC_EVENT_SNAPSHOT_ONLY", self.path.read_bytes())

    def test_hash_matches_input_bytes(self):
        import hashlib
        first = self.add()
        self.assertEqual(
            first["payload"]["content_sha256"],
            hashlib.sha256(b"SYNTHETIC_EVENT_SNAPSHOT_ONLY").hexdigest(),
        )

    def test_time_boundary_pass_not_certified(self):
        first = self.add()
        decision = self.at_delay(first, 30)
        result = self.registry.audit("SYN-E1", decision)
        self.assertEqual(result["status"], "TIME_GATE_PASS_UNVERIFIED")
        self.assertTrue(result["time_gate_pass"])
        self.assertFalse(result["pit_certified"])
        self.assertTrue(result["registry_integrity_verified"])

    def test_before_available_is_hold(self):
        first = self.add()
        result = self.registry.audit("SYN-E1", self.at_delay(first, 29))
        self.assertEqual(result["status"], "HOLD_AFTER_DECISION")
        self.assertFalse(result["time_gate_pass"])

    def test_early_decision_is_hold(self):
        first = self.add()
        result = self.registry.audit("SYN-E1", self.at_delay(first, -3))
        self.assertEqual(result["status"], "HOLD_AFTER_DECISION")

    def test_missing_evidence_is_hold(self):
        self.add()
        result = self.registry.audit("SYN-UNKNOWN", "2026-12-31T10:00:00Z")
        self.assertEqual(result["status"], "HOLD_EVIDENCE_NOT_FOUND")

    def test_reject_duplicate_id(self):
        self.add()
        with self.assertRaises(DuplicateEvidenceError):
            self.add()
        self.assertEqual(self.registry.verify()["entry_count"], 1)

    def test_reject_fork_without_supersedes(self):
        self.add()
        with self.assertRaises(RegistryValidationError):
            self.add(evidence_id="SYN-E2", revision_id="R2")

    def test_revision_chain(self):
        self.add()
        second = self.add(
            evidence_id="SYN-E2", revision_id="R2",
            supersedes_evidence_id="SYN-E1", content=b"REVISED_SYNTHETIC_SNAPSHOT",
        )
        self.assertEqual(second["entry_index"], 1)
        self.assertEqual(self.registry.verify()["entry_count"], 2)

    def test_reject_duplicate_revision(self):
        self.add()
        with self.assertRaises(DuplicateEvidenceError):
            self.add(evidence_id="SYN-E2", supersedes_evidence_id="SYN-E1")

    def test_reject_unknown_rights(self):
        with self.assertRaises(RegistryValidationError):
            self.add(rights_class="PUBLIC_NO_PERMISSION_CHECK")
        self.assertFalse(self.path.exists())

    def test_reject_naive_source_time(self):
        with self.assertRaises(RegistryValidationError):
            self.add(source_published_at="2026-01-02T10:00:00")

    def test_reject_boolean_latency(self):
        with self.assertRaises(RegistryValidationError):
            self.add(registered_latency_seconds=True)

    def test_tamper_detected_and_gate_fails_closed(self):
        first = self.add()
        s = self.path.read_text(encoding="utf-8")
        # Change one metadata value without recomputing the chain.
        s = s.replace('"revision_id":"R1"', '"revision_id":"RX"')
        self.path.write_text(s, encoding="utf-8", newline="\n")
        with self.assertRaises(LedgerIntegrityError):
            self.registry.verify()
        result = self.registry.audit("SYN-E1", self.at_delay(first, 40))
        self.assertEqual(result["status"], "HOLD_LEDGER_INTEGRITY")
        self.assertFalse(result["time_gate_pass"])

    def test_truncated_file_fail_closed(self):
        self.add()
        with self.path.open("ab") as f:
            f.write(b'{"partial":true')
        self.assertEqual(
            self.registry.audit("SYN-E1", "2026-12-31T10:00:00Z")["status"],
            "HOLD_LEDGER_INTEGRITY",
        )

    def test_no_silent_append_to_bad_history(self):
        self.add()
        with self.path.open("ab") as f:
            f.write(b"badline\n")
        old_bytes = self.path.read_bytes()
        with self.assertRaises(LedgerIntegrityError):
            self.add(evidence_id="SYN-E2", revision_id="R2", supersedes_evidence_id="SYN-E1")
        self.assertEqual(self.path.read_bytes(), old_bytes)

    def test_separate_document_has_independent_chain(self):
        self.add()
        self.add(evidence_id="SYN-E2", source_record_id="DOC2")
        self.assertEqual(self.registry.verify()["entry_count"], 2)


if __name__ == "__main__":
    unittest.main()
