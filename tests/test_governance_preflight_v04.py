"""Strict synthetic fixture tests; no provider credentials or network."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kario_pit.governance import GovernancePreflight
from kario_pit.governance.preflight import ASSERTION_VERSION
from kario_pit.registry import EvidenceLedger


class GovernancePreflightV04Tests(unittest.TestCase):
    T1 = "2026-01-02T10:00:00Z"
    T2 = "2026-01-02T10:01:00Z"
    T0 = "2026-01-02T09:59:59Z"
    D1 = "2026-01-02T10:00:30Z"
    D2 = "2026-01-02T10:01:30Z"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic" / "ledger.jsonl"
        self.ledger = EvidenceLedger(self.path)
        self.gov = GovernancePreflight(self.path, synthetic_fixture_ids={"SYN-GOV-R1", "SYN-GOV-R2"})

    def add(self, stamp=T1, **updates):
        args = dict(
            evidence_id="SYN-GOV-R1", provider_id="MOCK",
            source_record_id="SYN-GOV", revision_id="R1",
            source_published_at="2026-01-02T09:59:00Z",
            registered_latency_seconds=30,
            rights_class="SYNTHETIC_PUBLIC",
            content=b"SYNTHETIC_ONLY_R1",
        )
        args.update(updates)
        # Controlled timestamps are used only in synthetic tests.
        with patch("kario_pit.registry.ledger._utc_now", return_value=stamp):
            return self.ledger.append(**args)

    def pair(self, **updates):
        self.add()
        kwargs = dict(
            evidence_id="SYN-GOV-R2", revision_id="R2",
            supersedes_evidence_id="SYN-GOV-R1",
            source_published_at="2026-01-02T10:00:45Z",
            content=b"SYNTHETIC_ONLY_R2",
        )
        kwargs.update(updates)
        return self.add(self.T2, **kwargs)

    def check(self, decision=D1, use="PUBLIC_SYNTHETIC_DEMO", **updates):
        query = dict(
            provider_id="MOCK", source_record_id="SYN-GOV",
            decision_at=decision, requested_use=use,
        )
        query.update(updates)
        return self.gov.assess(**query)

    def claim(self, row, stamp="2026-01-02T10:00:01Z"):
        return {
            "schema_version": ASSERTION_VERSION,
            "assertion_kind": "LOCAL_OPERATOR_DECLARATION",
            "evidence_id": row["payload"]["evidence_id"],
            "entry_hash": row["entry_hash"],
            "asserted_at_utc": stamp,
        }

    def test_synthetic_public_fixture_policy_pass(self):
        self.add()
        r = self.check()
        self.assertEqual(r["status"], "SYNTHETIC_PREFLIGHT_PASS_UNATTESTED")
        self.assertTrue(r["synthetic_demo_policy_pass"])
        self.assertTrue(r["time_gate_pass"])

    def test_local_synthetic_fixture_policy_pass(self):
        self.add()
        r = self.check(use="LOCAL_SYNTHETIC_TEST")
        self.assertTrue(r["synthetic_demo_policy_pass"])

    def test_pit_never_certified_even_when_fixture_passes(self):
        self.add()
        r = self.check()
        for key in (
            "pit_certified", "independent_provenance_verified",
            "external_attestation_verified", "rights_legally_cleared",
        ):
            self.assertIs(r[key], False)

    def test_before_availability_is_hold(self):
        self.add()
        r = self.check(decision="2026-01-02T10:00:29Z")
        self.assertEqual(r["status"], "HOLD_NO_VERSION_AT_DECISION")
        self.assertFalse(r["synthetic_demo_policy_pass"])

    def test_without_fixture_allowlist_denies_selection(self):
        self.add()
        other = GovernancePreflight(self.path)
        r = other.assess(
            provider_id="MOCK", source_record_id="SYN-GOV",
            decision_at=self.D1, requested_use="PUBLIC_SYNTHETIC_DEMO",
        )
        self.assertEqual(r["status"], "HOLD_FIXTURE_ORIGIN_UNVERIFIED")
        self.assertIsNone(r["selected_evidence_id"])

    def test_cloud_processing_denied(self):
        self.add()
        r = self.check(use="CLOUD_PROCESSING")
        self.assertEqual(r["status"], "HOLD_INVALID_USE")
        self.assertNotIn("SYN-GOV-R1", json.dumps(r))

    def test_model_training_denied(self):
        self.add()
        self.assertEqual(self.check(use="MODEL_TRAINING")["status"], "HOLD_INVALID_USE")

    def test_unhashable_use_is_denied_not_exception(self):
        self.add()
        r = self.check(use=[])
        self.assertEqual(r["status"], "HOLD_INVALID_USE")

    def test_vendor_restricted_replay_never_bypassed(self):
        self.add(rights_class="VENDOR_RESTRICTED")
        r = self.check()
        self.assertEqual(r["status"], "HOLD_RIGHTS_POLICY")
        self.assertNotIn("SYN-GOV-R1", json.dumps(r))

    def test_owned_private_replay_denied(self):
        self.add(rights_class="OWNED_PRIVATE")
        self.assertEqual(self.check()["status"], "HOLD_RIGHTS_POLICY")

    def test_missing_ledger_is_hold(self):
        r = self.check()
        self.assertEqual(r["status"], "HOLD_LEDGER_MISSING")
        self.assertFalse(r["registry_integrity_verified"])

    def test_bad_ledger_hash_is_hold(self):
        self.add()
        raw = self.path.read_text(encoding="utf-8")
        self.path.write_text(raw.replace('"revision_id":"R1"', '"revision_id":"R9"'), encoding="utf-8", newline="\n")
        r = self.check()
        self.assertEqual(r["status"], "HOLD_LEDGER_INTEGRITY")

    def test_naive_decision_is_hold(self):
        self.add()
        self.assertEqual(self.check(decision="2026-01-02T10:00:30")["status"], "HOLD_INVALID_DECISION_AT")

    def test_operator_assertion_matches_but_no_attestation(self):
        row = self.add()
        r = self.check(source_assertion=self.claim(row))
        self.assertEqual(r["attestation_status"], "LOCAL_ASSERTION_MATCHED_UNVERIFIED")
        self.assertEqual(r["status"], "SYNTHETIC_PREFLIGHT_PASS_UNATTESTED")
        self.assertFalse(r["external_attestation_verified"])

    def test_operator_assertion_wrong_hash_is_hold(self):
        row = self.add()
        fake = self.claim(row)
        fake["entry_hash"] = "a" * 64
        r = self.check(source_assertion=fake)
        self.assertEqual(r["attestation_status"], "BINDING_MISMATCH")
        self.assertEqual(r["status"], "HOLD_SOURCE_ASSERTION")

    def test_operator_assertion_wrong_evidence_id_is_hold(self):
        row = self.add()
        fake = self.claim(row)
        fake["evidence_id"] = "SYN-GOV-OTHER"
        self.assertEqual(self.check(source_assertion=fake)["status"], "HOLD_SOURCE_ASSERTION")

    def test_operator_assertion_future_is_hold(self):
        row = self.add()
        fake = self.claim(row, stamp="2026-01-02T10:00:31Z")
        r = self.check(source_assertion=fake)
        self.assertEqual(r["attestation_status"], "FUTURE_ASSERTION_AT_DECISION")
        self.assertFalse(r["synthetic_demo_policy_pass"])

    def test_operator_assertion_naive_timestamp_is_hold(self):
        row = self.add()
        fake = self.claim(row, stamp="2026-01-02T10:00:00")
        r = self.check(source_assertion=fake)
        self.assertEqual(r["attestation_status"], "INVALID_TIMESTAMP")

    def test_unknown_external_proof_kind_is_rejected(self):
        row = self.add()
        fake = self.claim(row)
        fake["assertion_kind"] = "EXTERNAL_TSA_SIGNED"
        r = self.check(source_assertion=fake)
        self.assertEqual(r["attestation_status"], "UNSUPPORTED_ASSERTION")

    def test_unexpected_claim_field_is_rejected(self):
        row = self.add()
        fake = self.claim(row)
        fake["secret_data"] = "should not appear"
        r = self.check(source_assertion=fake)
        self.assertEqual(r["attestation_status"], "INVALID_FORMAT")
        self.assertNotIn("secret_data", json.dumps(r))

    def test_revision_asof_R1_not_future_R2(self):
        self.pair()
        r = self.check()
        self.assertEqual(r["selected_revision_id"], "R1")
        self.assertNotIn("SYN-GOV-R2", json.dumps(r))

    def test_revision_R2_after_available(self):
        self.pair()
        r = self.check(decision=self.D2)
        self.assertEqual(r["selected_revision_id"], "R2")

    def test_unallowlisted_later_revision_is_hold(self):
        self.pair()
        other = GovernancePreflight(self.path, synthetic_fixture_ids={"SYN-GOV-R1"})
        r = other.assess(
            provider_id="MOCK", source_record_id="SYN-GOV",
            decision_at=self.D2, requested_use="PUBLIC_SYNTHETIC_DEMO",
        )
        self.assertEqual(r["status"], "HOLD_FIXTURE_ORIGIN_UNVERIFIED")

    def test_replay_preflight_read_only(self):
        self.pair()
        original = self.path.read_bytes()
        self.check()
        self.check(decision=self.D2)
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_fixture_ids_raise(self):
        with self.assertRaises(ValueError):
            GovernancePreflight(self.path, synthetic_fixture_ids=["../../../bad"])

    def test_false_source_id_returns_hold(self):
        self.add()
        r = self.check(source_record_id="DIFFERENT")
        self.assertEqual(r["status"], "HOLD_SOURCE_NOT_FOUND")

    def test_missing_assertion_is_unverified_not_an_error(self):
        self.add()
        self.assertEqual(self.check()["attestation_status"], "MISSING")


if __name__ == "__main__":
    unittest.main()
