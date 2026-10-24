"""Synthetic/owned-local tests only. No restricted provider sample material."""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from kario_pit.intake import IntakeError, import_local_file
from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer

FIELDS = [
    "evidence_id", "provider_id", "source_record_id", "revision_id",
    "supersedes_evidence_id", "source_published_at",
    "registered_latency_seconds", "rights_class", "content_text",
]


class LocalIntakeV06Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kario_v06_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.jsonl"
        self.ledger = self.root / "local_ledger.jsonl"
        self.base = {
            "evidence_id": "SYN-001", "provider_id": "SYNTHETIC",
            "source_record_id": "SYN-DOC", "revision_id": "R1",
            "supersedes_evidence_id": None,
            "source_published_at": "2026-01-01T10:00:00Z",
            "registered_latency_seconds": 0,
            "rights_class": "SYNTHETIC_PUBLIC",
            "content_text": "SYNTHETIC DEMO ONE",
        }

    def record(self, **kwargs):
        return {**self.base, **kwargs}

    def put(self, rows=None, source=None):
        p = source or self.source
        rows = rows if rows is not None else [self.record()]
        p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        return p

    def put_csv(self, rows=None):
        path = self.root / "input.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            for r in (rows if rows is not None else [self.record()]):
                writer.writerow(r)
        return path

    def ingest(self, rows=None, **kwargs):
        self.put(rows)
        return import_local_file(self.source, self.ledger, **kwargs)

    def assert_hold(self, rows=None, **kwargs):
        self.put(rows)
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, **kwargs)
        self.assertFalse(self.ledger.exists())

    def test_synthetic_jsonl_dry_run_read_only(self):
        result = self.ingest()
        self.assertEqual(result["status"], "DRY_RUN_LOCAL_UNATTESTED")
        self.assertFalse(result["batch_committed"])
        self.assertFalse(self.ledger.exists())

    def test_synthetic_jsonl_commit(self):
        result = self.ingest(apply=True)
        self.assertTrue(result["batch_committed"])
        self.assertEqual(EvidenceLedger(self.ledger).verify()["entry_count"], 1)

    def test_synthetic_csv_dry_run(self):
        p = self.put_csv()
        result = import_local_file(p, self.ledger)
        self.assertEqual(result["records_in_batch"], 1)
        self.assertFalse(self.ledger.exists())

    def test_synthetic_csv_commit(self):
        p = self.put_csv()
        self.assertTrue(import_local_file(p, self.ledger, apply=True)["batch_committed"])
        self.assertEqual(EvidenceLedger(self.ledger).verify()["entry_count"], 1)

    def test_raw_text_not_in_metadata_ledger(self):
        self.ingest(apply=True)
        self.assertNotIn("SYNTHETIC DEMO ONE", self.ledger.read_text())

    def test_all_trust_flags_false(self):
        r = self.ingest(apply=True)
        for key in ("pit_certified", "trusted_time_verified", "rights_legally_cleared",
                    "private_data_public_export_authorized", "source_published_time_independently_verified"):
            self.assertIs(r[key], False)

    def test_time_basis_unattested(self):
        self.ingest(apply=True)
        p = EvidenceLedger(self.ledger)._verify_and_load()[0]["payload"]
        self.assertEqual(p["time_basis"], "LOCAL_INGEST_RECEIPT_UNATTESTED")

    def test_replay_r1_r2_no_backport(self):
        rows = [self.record(), self.record(evidence_id="SYN-002", revision_id="R2",
                                          supersedes_evidence_id="SYN-001", content_text="SYNTHETIC NEW")]
        self.ingest(rows, apply=True)
        ledger = EvidenceLedger(self.ledger)
        recorded = ledger._verify_and_load()
        rp = DecisionReplayer(self.ledger)
        old = rp.replay_document(provider_id="SYNTHETIC", source_record_id="SYN-DOC",
                                 decision_at=recorded[0]["recorded_at_utc"])
        self.assertEqual(old["selected_revision_id"], "R1")
        self.assertFalse(old["pit_certified"])
        newer = rp.replay_document(provider_id="SYNTHETIC", source_record_id="SYN-DOC",
            decision_at=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat())
        self.assertEqual(newer["selected_revision_id"], "R2")

    def test_second_batch_revision_correct(self):
        self.ingest(apply=True)
        row = self.record(evidence_id="SYN-002", revision_id="R2", supersedes_evidence_id="SYN-001")
        self.put([row])
        r = import_local_file(self.source, self.ledger, apply=True)
        self.assertEqual(r["ledger_entries_before"], 1)
        self.assertEqual(EvidenceLedger(self.ledger).verify()["entry_count"], 2)

    def test_original_ledger_preserved_if_invalid_second_batch(self):
        self.ingest(apply=True)
        before = self.ledger.read_bytes()
        self.put([self.record(evidence_id="SYN-003", revision_id="R3", supersedes_evidence_id="SYN-404")])
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, apply=True)
        self.assertEqual(before, self.ledger.read_bytes())

    def test_atomic_batch_invalid_second_row(self):
        a = self.record()
        b = self.record(evidence_id="SYN-002", revision_id="R2", supersedes_evidence_id="WRONG")
        self.assert_hold([a, b], apply=True)

    def test_existing_duplicate_input_refused(self):
        self.ingest(apply=True)
        before = self.ledger.read_bytes()
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, apply=True)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_ledger_integrity_fail_closed_dry_run(self):
        self.ledger.write_bytes(b'{"tampered":true}\n')
        self.put()
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_ledger_integrity_fail_closed_commit(self):
        self.ledger.write_bytes(b'{"tampered":true}\n')
        self.put()
        before = self.ledger.read_bytes()
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, apply=True)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_private_missing_ack_refused(self):
        own = self.record(evidence_id="P-001", provider_id="INTERNAL", rights_class="OWNED_PRIVATE")
        self.assert_hold([own], mode="LOCAL_OWNED_PRIVATE", apply=True)

    def test_private_ack_local_commit(self):
        own = self.record(evidence_id="P-001", provider_id="INTERNAL", rights_class="OWNED_PRIVATE",
                          content_text="LOCAL-SECRET-EXAMPLE")
        r = self.ingest([own], mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)
        self.assertTrue(r["batch_committed"])
        self.assertFalse(r["rights_legally_cleared"])
        self.assertNotIn("LOCAL-SECRET-EXAMPLE", self.ledger.read_text())

    def test_private_replay_remains_hold(self):
        own = self.record(evidence_id="P-001", provider_id="INTERNAL", rights_class="OWNED_PRIVATE")
        self.ingest([own], mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)
        r = DecisionReplayer(self.ledger).replay_document(provider_id="INTERNAL", source_record_id="SYN-DOC",
             decision_at=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat())
        self.assertEqual(r["status"], "HOLD_RIGHTS_POLICY")

    def test_vendor_restricted_denied_even_with_private_ack(self):
        own = self.record(evidence_id="P-001", provider_id="EXTERNAL", rights_class="VENDOR_RESTRICTED")
        self.assert_hold([own], mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)

    def test_private_mode_wrong_class_denied(self):
        self.assert_hold(mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)

    def test_unknown_mode_denied(self):
        self.assert_hold(mode="CLOUD_UPLOAD", apply=True)

    def test_cloud_export_cannot_be_requested(self):
        self.put()
        with self.assertRaises(TypeError):
            import_local_file(self.source, self.ledger, cloud_export=True)

    def test_synthetic_id_prefix_required(self):
        self.assert_hold([self.record(evidence_id="E-01")], apply=True)

    def test_synthetic_provider_fixed(self):
        self.assert_hold([self.record(provider_id="OTHER")], apply=True)

    def test_missing_field_denied(self):
        r = self.record(); r.pop("content_text")
        self.assert_hold([r], apply=True)

    def test_extra_field_denied(self):
        self.assert_hold([self.record(extra="x")], apply=True)

    def test_duplicate_json_key_denied(self):
        self.source.write_text('{"evidence_id":"SYN-001","evidence_id":"SYN-002"}\n')
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, apply=True)

    def test_nan_denied(self):
        self.source.write_text(json.dumps(self.record())[:-1] + ',"noise":NaN}\n')
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, apply=True)

    def test_blank_jsonl_line_denied(self):
        self.put()
        with self.source.open("a") as f: f.write("\n")
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_unsupported_extension_denied(self):
        p = self.put(source=self.root / "input.txt")
        with self.assertRaises(IntakeError):
            import_local_file(p, self.ledger)

    def test_invalid_utf8_denied(self):
        self.source.write_bytes(b'\xff\xfe')
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_nul_byte_denied(self):
        self.source.write_bytes(b'\x00')
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_empty_input_denied(self):
        self.source.write_bytes(b'')
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_file_limit_denied(self):
        self.source.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger)

    def test_batch_101_denied(self):
        rows = [self.record(evidence_id=f"SYN-{i:03}", source_record_id=f"DOC-{i:03}") for i in range(101)]
        self.assert_hold(rows, apply=True)

    def test_blank_content_denied(self):
        self.assert_hold([self.record(content_text="")], apply=True)

    def test_future_published_refused(self):
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        self.assert_hold([self.record(source_published_at=future)], apply=True)

    def test_naive_time_refused(self):
        self.assert_hold([self.record(source_published_at="2026-01-01T10:00:00")], apply=True)

    def test_negative_latency_refused(self):
        self.assert_hold([self.record(registered_latency_seconds=-1)], apply=True)

    def test_boolean_latency_refused(self):
        self.assert_hold([self.record(registered_latency_seconds=True)], apply=True)

    def test_excessive_latency_refused(self):
        self.assert_hold([self.record(registered_latency_seconds=604801)], apply=True)

    def test_zero_prefixed_csv_latency_refused(self):
        p = self.put_csv([self.record(registered_latency_seconds="00")])
        with self.assertRaises(IntakeError):
            import_local_file(p, self.ledger)

    def test_csv_header_duplicate_refused(self):
        p = self.root / "input.csv"
        p.write_text("evidence_id,evidence_id\nSYN-1,SYN-2\n")
        with self.assertRaises(IntakeError):
            import_local_file(p, self.ledger)

    def test_utf8_bom_csv_allowed(self):
        p = self.put_csv()
        p.write_bytes(b'\xef\xbb\xbf' + p.read_bytes())
        r = import_local_file(p, self.ledger)
        self.assertEqual(r["records_in_batch"], 1)

    def test_input_symlink_refused(self):
        self.put()
        with mock.patch.object(Path, "is_symlink", autospec=True,
                               side_effect=lambda p: p == self.source):
            with self.assertRaises(IntakeError):
                import_local_file(self.source, self.ledger)

    def test_destination_symlink_refused(self):
        self.put()
        with mock.patch.object(Path, "is_symlink", autospec=True,
                               side_effect=lambda p: p == self.ledger):
            with self.assertRaises(IntakeError):
                import_local_file(self.source, self.ledger)

    def test_input_and_output_same_file_denied(self):
        self.put()
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.source, apply=True)

    def test_active_writer_lock_refused(self):
        self.put()
        lock = Path(str(self.ledger) + ".lock")
        lock.write_text("locked")
        with self.assertRaises(Exception):
            import_local_file(self.source, self.ledger, apply=True)
        self.assertFalse(self.ledger.exists())

    def test_metadata_and_hash_do_not_certify_rights(self):
        self.ingest(apply=True)
        r = EvidenceLedger(self.ledger).audit("SYN-001", (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat())
        self.assertFalse(r["pit_certified"])

    def test_input_jsonl_newline_windows(self):
        raw = json.dumps(self.record()) + "\r\n"
        self.source.write_bytes(raw.encode())
        r = import_local_file(self.source, self.ledger, apply=True)
        self.assertTrue(r["batch_committed"])

    def test_mixed_rights_batch_refused(self):
        rows = [self.record(), self.record(evidence_id="P-002", provider_id="INTERNAL", rights_class="OWNED_PRIVATE")]
        self.assert_hold(rows, apply=True)

    def test_existing_source_rights_cannot_switch(self):
        self.ingest(apply=True)
        before = self.ledger.read_bytes()
        own = self.record(evidence_id="P-002", revision_id="R2", supersedes_evidence_id="SYN-001", rights_class="OWNED_PRIVATE")
        self.put([own])
        with self.assertRaises(IntakeError):
            import_local_file(self.source, self.ledger, mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)
        self.assertEqual(before, self.ledger.read_bytes())

    def test_duplicate_revision_in_batch_refused(self):
        rows = [self.record(), self.record(evidence_id="SYN-002", revision_id="R1", supersedes_evidence_id="SYN-001")]
        self.assert_hold(rows, apply=True)

    def test_no_bogus_synthetic_prefix_private(self):
        own = self.record(evidence_id="PERSON-1", provider_id="OWNED", rights_class="OWNED_PRIVATE")
        self.ingest([own], mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)
        self.assertEqual(EvidenceLedger(self.ledger).verify()["entry_count"], 1)


    def test_staging_append_failure_preserves_original_ledger(self):
        self.ingest(apply=True)
        original = self.ledger.read_bytes()
        row = self.record(evidence_id="SYN-002", revision_id="R2",
                          supersedes_evidence_id="SYN-001")
        self.put([row])
        with mock.patch("kario_pit.intake.vendor_neutral_v06.EvidenceLedger.append",
                        side_effect=OSError("synthetic staged-disk failure")):
            with self.assertRaises(OSError):
                import_local_file(self.source, self.ledger, apply=True)
        self.assertEqual(self.ledger.read_bytes(), original)
        self.assertFalse(list(self.root.glob(".kario_v06_stage_*.jsonl")))

    def test_ledger_has_no_stage_files_after_success(self):
        self.ingest(apply=True)
        self.assertFalse(list(self.root.glob(".kario_v06_stage_*.jsonl")))

    def test_private_not_exportable_via_demo_gate(self):
        own = self.record(evidence_id="PERSON-1", provider_id="OWNED", rights_class="OWNED_PRIVATE")
        self.ingest([own], mode="LOCAL_OWNED_PRIVATE", acknowledge_private_rights=True, apply=True)
        result = EvidenceLedger(self.ledger).verify()
        self.assertEqual(result["status"], "STRUCTURALLY_VALID_NOT_INDEPENDENTLY_ATTESTED")


if __name__ == "__main__":
    unittest.main()
