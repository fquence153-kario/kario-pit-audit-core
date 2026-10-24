"""Fail-closed private local audit tests. All input strings are synthetic."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from kario_pit.registry import EvidenceLedger
from kario_pit.private.local_audit_v07 import (
    PrivateLocalAuditor, SCHEMA_VERSION,
)
from kario_pit.replay import DecisionReplayer
from kario_pit.audit.time_gate import parse_utc


class PrivateAuditV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kario_v07_tests_")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / "private.jsonl"
        self.ledger = EvidenceLedger(self.path)
        self.published = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.row1 = self._append("CASE1", "R1", "P1", rights="OWNED_PRIVATE")
        self.t1 = self.row1["recorded_at_utc"]

    def _append(self, eid, rev, source, *, rights="OWNED_PRIVATE", previous=None,
                published="DEFAULT", latency=0, provider="CUSTOMER_OWNED_DEMO"):
        return self.ledger.append(
            evidence_id=eid,
            provider_id=provider,
            source_record_id=source,
            revision_id=rev,
            supersedes_evidence_id=previous,
            content=b"synthetic private-labelled fixture only, never real client content",
            source_published_at=self.published if published == "DEFAULT" else published,
            registered_latency_seconds=latency,
            rights_class=rights,
        )

    def _sha(self):
        return sha256(self.path.read_bytes()).hexdigest()

    def _call(self, **kw):
        args = dict(
            provider_id="CUSTOMER_OWNED_DEMO",
            source_record_id="P1",
            decision_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
            acknowledge_local_rights=True,
        )
        args.update(kw)
        if "expected_ledger_sha256" not in args:
            args["expected_ledger_sha256"] = self._sha()
        return PrivateLocalAuditor(self.path).audit_document(**args)

    def _r2(self, *, latency=0, published="DEFAULT"):
        return self._append("CASE2", "R2", "P1", previous="CASE1", latency=latency,
                            published=published)

    def test_private_local_pass_is_unattested(self):
        x = self._call()
        self.assertEqual(x["status"], "LOCAL_PRIVATE_TIME_GATE_PASS_UNATTESTED")
        self.assertTrue(x["time_gate_pass"])
        self.assertTrue(x["private_version_selected"])

    def test_default_result_redacts_ids(self):
        x = self._call()
        for key in ("selected_evidence_id", "selected_revision_id", "selected_entry_hash",
                    "selected_content_sha256", "effective_available_at_utc"):
            self.assertNotIn(key, x)
        self.assertTrue(x["private_details_redacted"])

    def test_public_replay_still_denies_private(self):
        x = DecisionReplayer(self.path).replay_document(
            provider_id="CUSTOMER_OWNED_DEMO", source_record_id="P1",
            decision_at=self._call_decision())
        self.assertEqual(x["status"], "HOLD_RIGHTS_POLICY")

    def _call_decision(self):
        return (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

    def test_detail_requires_second_ack(self):
        self.assertEqual(self._call(detail_level="LOCAL_FULL")["status"],
                         "HOLD_PRIVATE_DETAIL_ACK_REQUIRED")

    def test_detail_local_full_explicit(self):
        x = self._call(detail_level="LOCAL_FULL", acknowledge_private_detail=True)
        self.assertFalse(x["private_details_redacted"])
        self.assertEqual(x["selected_revision_id"], "R1")
        self.assertEqual(x["selected_evidence_id"], "CASE1")

    def test_future_revision_never_backported(self):
        self._r2()
        x = self._call(decision_at=self.t1, detail_level="LOCAL_FULL", acknowledge_private_detail=True)
        self.assertEqual(x["selected_revision_id"], "R1")

    def test_r2_selected_after_receipt(self):
        self._r2()
        x = self._call(detail_level="LOCAL_FULL", acknowledge_private_detail=True)
        self.assertEqual(x["selected_revision_id"], "R2")

    def test_r2_latency_not_effective_selects_r1(self):
        r2 = self._r2(latency=30)
        x = self._call(decision_at=r2["recorded_at_utc"], detail_level="LOCAL_FULL",
                       acknowledge_private_detail=True)
        self.assertEqual(x["selected_revision_id"], "R1")

    def test_r2_after_latency_selects_r2(self):
        r2 = self._r2(latency=30)
        at = (parse_utc(r2["recorded_at_utc"]) + timedelta(seconds=31)).isoformat()
        x = self._call(decision_at=at, detail_level="LOCAL_FULL", acknowledge_private_detail=True)
        self.assertEqual(x["selected_revision_id"], "R2")

    def test_before_first_observed_hold(self):
        at = (parse_utc(self.t1) - timedelta(seconds=1)).isoformat()
        self.assertEqual(self._call(decision_at=at)["status"], "HOLD_NO_VERSION_AT_DECISION")

    def test_first_receipt_time_inclusive(self):
        self.assertTrue(self._call(decision_at=self.t1)["time_gate_pass"])

    def test_rights_ack_absent_hold(self):
        self.assertEqual(self._call(acknowledge_local_rights=False)["status"],
                         "HOLD_RIGHTS_ACK_REQUIRED")

    def test_ack_string_not_true(self):
        self.assertEqual(self._call(acknowledge_local_rights="true")["status"],
                         "HOLD_INVALID_USE")

    def test_ack_false_bool_supported_and_denied(self):
        self.assertEqual(self._call(acknowledge_local_rights=False)["status"],
                         "HOLD_RIGHTS_ACK_REQUIRED")

    def test_wrong_use_cloud(self):
        self.assertEqual(self._call(requested_use="CLOUD_PRIVATE_AUDIT")["status"],
                         "HOLD_INVALID_USE")

    def test_wrong_use_training(self):
        self.assertEqual(self._call(requested_use="MODEL_TRAINING")["status"],
                         "HOLD_INVALID_USE")

    def test_wrong_use_public_export(self):
        self.assertEqual(self._call(requested_use="PUBLIC_EXPORT")["status"],
                         "HOLD_INVALID_USE")

    def test_invalid_detail_level(self):
        self.assertEqual(self._call(detail_level="UNMASK_ALL")["status"],
                         "HOLD_INVALID_USE")

    def test_vendor_restricted_whole_ledger_denied(self):
        self._append("VENDOR1", "R1", "VEND", rights="VENDOR_RESTRICTED",
                     provider="THIRD_PARTY")
        x = self._call()
        self.assertEqual(x["status"], "HOLD_LEDGER_NOT_PRIVATE_ONLY")
        self.assertFalse(x["time_gate_pass"])

    def test_public_synthetic_in_private_ledger_denied(self):
        self._append("SYN-1", "R1", "SYNSRC", rights="SYNTHETIC_PUBLIC",
                     provider="SYNTHETIC")
        self.assertEqual(self._call()["status"], "HOLD_LEDGER_NOT_PRIVATE_ONLY")

    def test_wrong_provider_query_hold(self):
        self.assertEqual(self._call(provider_id="UNKNOWN")["status"],
                         "HOLD_SOURCE_NOT_FOUND")

    def test_invalid_source_id_hold(self):
        self.assertEqual(self._call(source_record_id="../sneaky")["status"],
                         "HOLD_INVALID_QUERY")

    def test_invalid_decision_timestamp(self):
        self.assertEqual(self._call(decision_at="2026-10-09T14:00:00")["status"],
                         "HOLD_INVALID_DECISION_TIME")

    def test_wrong_pin_denied(self):
        self.assertEqual(self._call(expected_ledger_sha256="0"*64)["status"],
                         "HOLD_LEDGER_PIN_MISMATCH")

    def test_no_pin_denied(self):
        self.assertEqual(self._call(expected_ledger_sha256="")["status"],
                         "HOLD_LEDGER_PIN_INVALID")

    def test_pin_uppercase_denied(self):
        self.assertEqual(self._call(expected_ledger_sha256=self._sha().upper())["status"],
                         "HOLD_LEDGER_PIN_INVALID")

    def test_corrupted_ledger_denied(self):
        self.path.write_bytes(self.path.read_bytes().replace(b"OWNED_PRIVATE", b"VENDOR_RESTRICTED"))
        self.assertEqual(self._call()["status"], "HOLD_LEDGER_INTEGRITY")

    def test_missing_ledger_denied(self):
        self.path.unlink()
        self.assertEqual(self._call(expected_ledger_sha256="0"*64)["status"],
                         "HOLD_LEDGER_MISSING")

    def test_symlink_path_denied_even_when_mocked(self):
        with patch.object(Path, "is_symlink", return_value=True):
            self.assertEqual(self._call()["status"], "HOLD_UNSAFE_LEDGER_PATH")

    def test_ledger_inside_repo_denied(self):
        with patch("kario_pit.private.local_audit_v07.PROJECT_ROOT", self.base):
            self.assertEqual(self._call()["status"], "HOLD_LEDGER_INSIDE_SOURCE_TREE")

    def test_mid_audit_digest_change_denied(self):
        with patch("kario_pit.private.local_audit_v07._file_sha256",
                   side_effect=[self._sha(), "0"*64]):
            self.assertEqual(self._call()["status"], "HOLD_LEDGER_CHANGED_DURING_AUDIT")

    def test_missing_source_published_denied(self):
        p = self.base / "missing_source.jsonl"
        e = EvidenceLedger(p)
        e.append(evidence_id="A", provider_id="CUSTOMER_OWNED_DEMO",
                 source_record_id="P1", revision_id="R1", content=b"synthetic",
                 rights_class="OWNED_PRIVATE", registered_latency_seconds=0,
                 source_published_at=None)
        h = sha256(p.read_bytes()).hexdigest()
        x = PrivateLocalAuditor(p).audit_document(provider_id="CUSTOMER_OWNED_DEMO",
            source_record_id="P1", decision_at=self._call_decision(),
            expected_ledger_sha256=h, acknowledge_local_rights=True)
        self.assertEqual(x["status"], "HOLD_SOURCE_TIME_MISSING")

    def test_future_source_publish_chronology_denied(self):
        p = self.base / "future_publish.jsonl"
        e = EvidenceLedger(p)
        e.append(evidence_id="A", provider_id="CUSTOMER_OWNED_DEMO",
                 source_record_id="P1", revision_id="R1", content=b"synthetic",
                 rights_class="OWNED_PRIVATE", registered_latency_seconds=0,
                 source_published_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
        h = sha256(p.read_bytes()).hexdigest()
        x = PrivateLocalAuditor(p).audit_document(provider_id="CUSTOMER_OWNED_DEMO",
            source_record_id="P1", decision_at=self._call_decision(),
            expected_ledger_sha256=h, acknowledge_local_rights=True)
        self.assertEqual(x["status"], "HOLD_CHRONOLOGY_CONFLICT")

    def test_revision_source_time_regression_denied(self):
        early = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        self._r2(published=early)
        self.assertEqual(self._call()["status"], "HOLD_REVISION_TIME_REGRESSION")

    def test_source_and_ledger_not_modified_by_audit(self):
        before = self.path.read_bytes()
        self._call()
        self.assertEqual(before, self.path.read_bytes())

    def test_no_pit_certification_or_legal_clearance(self):
        x = self._call()
        for key in ("rights_legally_cleared", "trusted_time_verified", "pit_certified",
                    "external_export_authorized", "production_ready", "model_training_authorized",
                    "source_time_independently_verified"):
            self.assertIs(x[key], False)
        self.assertEqual(x["rights_source"], "OPERATOR_DECLARED_NOT_VERIFIED")

    def test_no_client_content_in_minimal_report(self):
        data = json.dumps(self._call())
        self.assertNotIn("synthetic private-labelled fixture", data)
        self.assertNotIn("CASE1", data)
        self.assertNotIn("CUSTOMER_OWNED_DEMO", data)
        self.assertNotIn(self._sha(), data)

    def test_minimal_schema_contract(self):
        x = self._call()
        self.assertEqual(x["schema_version"], SCHEMA_VERSION)
        self.assertEqual(x["evidence_proof_class"], "LOCAL_INGEST_RECEIPT_UNATTESTED")

    def test_cli_redacted_no_details(self):
        cli = Path(__file__).resolve().parents[1] / "tools" / "private_local_audit_v07.py"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        p = subprocess.run([
            sys.executable, str(cli), "--ledger", str(self.path),
            "--provider", "CUSTOMER_OWNED_DEMO", "--source-record", "P1",
            "--decision-at", self._call_decision(), "--expected-ledger-sha256", self._sha(),
            "--acknowledge-private-rights",
        ], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "LOCAL_PRIVATE_TIME_GATE_PASS_UNATTESTED")
        self.assertNotIn("CASE1", p.stdout)
        self.assertNotIn("CUSTOMER_OWNED_DEMO", p.stdout)
        self.assertNotIn(str(self.path), p.stdout)
        self.assertNotIn(self._sha(), p.stdout)

    def test_cli_without_ack_denied(self):
        cli = Path(__file__).resolve().parents[1] / "tools" / "private_local_audit_v07.py"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        p = subprocess.run([
            sys.executable, str(cli), "--ledger", str(self.path),
            "--provider", "CUSTOMER_OWNED_DEMO", "--source-record", "P1",
            "--decision-at", self._call_decision(), "--expected-ledger-sha256", self._sha(),
        ], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD_RIGHTS_ACK_REQUIRED")


if __name__ == "__main__":
    unittest.main()
