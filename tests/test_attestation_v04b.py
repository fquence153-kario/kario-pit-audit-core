"""Offline synthetic Ed25519 signature laboratory. No vendor integration."""
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kario_pit.attestation import SignedReceiptLabVerifier, RECEIPT_VERSION, signing_message
from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer


class SignedReceiptLabV04BTests(unittest.TestCase):
    T1 = "2026-01-02T10:00:00Z"
    T2 = "2026-01-02T10:01:00Z"
    D1 = "2026-01-02T10:00:30Z"
    D2 = "2026-01-02T10:01:30Z"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"
        self.ledger = EvidenceLedger(self.path)
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.key.public_key().public_bytes_raw()).decode("ascii")
        self.signers = {
            "LAB-KEY-01": {
                "public_key_b64": self.public,
                "usage": "SYNTHETIC_LAB_ONLY",
                "not_before_utc": "2026-01-01T00:00:00Z",
                "not_after_utc": "2026-01-03T00:00:00Z",
                "revoked": False,
            }
        }
        self.fixture_ids = {"SYN-ED25519-R1", "SYN-ED25519-R2"}
        self.verifier = self.make_verifier()
        self.query = dict(
            provider_id="MOCK", source_record_id="LAB-DOC-01",
            decision_at=self.D1, requested_use="PUBLIC_SYNTHETIC_DEMO",
        )

    def make_verifier(self, *, signers=None, ids=None):
        return SignedReceiptLabVerifier(
            self.path,
            synthetic_fixture_ids=self.fixture_ids if ids is None else ids,
            lab_signers=self.signers if signers is None else signers,
        )

    def add_r1(self, *, rights="SYNTHETIC_PUBLIC"):
        with patch("kario_pit.registry.ledger._utc_now", return_value=self.T1):
            return self.ledger.append(
                evidence_id="SYN-ED25519-R1",
                provider_id="MOCK", source_record_id="LAB-DOC-01",
                revision_id="R1", content=b"SYNTHETIC-R1-ONLY",
                registered_latency_seconds=30,
                rights_class=rights,
                source_published_at="2026-01-02T09:59:59Z",
            )

    def add_r2(self):
        with patch("kario_pit.registry.ledger._utc_now", return_value=self.T2):
            return self.ledger.append(
                evidence_id="SYN-ED25519-R2",
                provider_id="MOCK", source_record_id="LAB-DOC-01",
                revision_id="R2", content=b"SYNTHETIC-R2-ONLY",
                registered_latency_seconds=30,
                rights_class="SYNTHETIC_PUBLIC",
                source_published_at="2026-01-02T10:00:59Z",
                supersedes_evidence_id="SYN-ED25519-R1",
            )

    def sign(self, *, query=None, issued=None, key_id="LAB-KEY-01", key=None):
        query = query or self.query
        replay = DecisionReplayer(self.path).replay_document(
            provider_id=query["provider_id"],
            source_record_id=query["source_record_id"],
            decision_at=query["decision_at"],
        )
        self.assertEqual(replay["status"], "TIME_GATE_PASS_UNVERIFIED")
        claims = dict(
            proof_kind="SYNTHETIC_LAB_ED25519",
            evidence_id=replay["selected_evidence_id"],
            revision_id=replay["selected_revision_id"],
            entry_hash=replay["selected_entry_hash"],
            content_sha256=replay["selected_content_sha256"],
            provider_id=query["provider_id"],
            source_record_id=query["source_record_id"],
            decision_at_utc=replay["decision_at_utc"],
            effective_available_at_utc=replay["selected_available_at_utc"],
            claimed_signed_at_utc=issued or replay["decision_at_utc"],
        )
        unsigned = {
            "schema_version": RECEIPT_VERSION,
            "key_id": key_id,
            "claims": claims,
        }
        sig = (key or self.key).sign(signing_message(unsigned))
        return {**unsigned, "signature_b64": base64.b64encode(sig).decode("ascii")}

    def test_valid_signature_is_not_independent_time_or_pit(self):
        self.add_r1()
        out = self.verifier.assess(**self.query, signed_receipt=self.sign())
        self.assertEqual(out["status"], "SYNTHETIC_SIGNATURE_VALID_UNATTESTED")
        self.assertTrue(out["signature_valid"])
        self.assertTrue(out["binding_verified"])
        self.assertTrue(out["signed_clock_claim_consistent"])
        for name in (
            "trusted_time_verified", "external_attestation_verified",
            "independent_provenance_verified", "rights_legally_cleared",
            "pit_certified",
        ):
            self.assertIs(out[name], False)

    def test_missing_receipt_hold(self):
        self.add_r1()
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=None)["status"], "HOLD_RECEIPT_MISSING")

    def test_modified_signature_invalid(self):
        self.add_r1()
        x = self.sign()
        x["signature_b64"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_SIGNATURE_INVALID")

    def test_wrong_cryptographic_key_rejected(self):
        self.add_r1()
        other_key = Ed25519PrivateKey.generate()
        x = self.sign(key=other_key)
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_SIGNATURE_INVALID")

    def test_bad_signature_encoding_rejected(self):
        self.add_r1()
        x = self.sign()
        x["signature_b64"] = "%%broken%%"
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_bad_signature_size_rejected(self):
        self.add_r1()
        x = self.sign()
        x["signature_b64"] = base64.b64encode(b"a" * 30).decode("ascii")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_missing_claim_rejected(self):
        self.add_r1()
        x = self.sign()
        del x["claims"]["revision_id"]
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_extra_claim_rejected(self):
        self.add_r1()
        x = self.sign()
        x["claims"]["hidden"] = "xyz"
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_extra_top_level_field_rejected(self):
        self.add_r1()
        x = self.sign()
        x["magic"] = "bypass"
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_wrong_signed_content_hash_binding_denied(self):
        self.add_r1()
        x = self.sign()
        x["claims"]["content_sha256"] = "a" * 64
        unsigned = {k: x[k] for k in ("schema_version", "key_id", "claims")}
        x["signature_b64"] = base64.b64encode(self.key.sign(signing_message(unsigned))).decode("ascii")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_BINDING_MISMATCH")

    def test_wrong_signed_entry_hash_binding_denied(self):
        self.add_r1()
        x = self.sign()
        x["claims"]["entry_hash"] = "a" * 64
        unsigned = {k: x[k] for k in ("schema_version", "key_id", "claims")}
        x["signature_b64"] = base64.b64encode(self.key.sign(signing_message(unsigned))).decode("ascii")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_BINDING_MISMATCH")

    def test_unknown_signer_rejected_even_with_valid_signature(self):
        self.add_r1()
        x = self.sign(key_id="LAB-OTHER-KEY")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_UNKNOWN_SIGNER")

    def test_no_trust_store_is_fail_closed(self):
        self.add_r1()
        x = self.sign()
        v = self.make_verifier(signers={})
        self.assertEqual(v.assess(**self.query, signed_receipt=x)["status"], "HOLD_UNKNOWN_SIGNER")

    def test_revoked_signer_rejected(self):
        self.add_r1()
        x = self.sign()
        signers = copy.deepcopy(self.signers)
        signers["LAB-KEY-01"]["revoked"] = True
        self.assertEqual(self.make_verifier(signers=signers).assess(**self.query, signed_receipt=x)["status"], "HOLD_SIGNER_REVOKED")

    def test_signer_not_yet_active(self):
        self.add_r1()
        x = self.sign()
        signers = copy.deepcopy(self.signers)
        signers["LAB-KEY-01"]["not_before_utc"] = "2026-01-02T10:01:00Z"
        self.assertEqual(self.make_verifier(signers=signers).assess(**self.query, signed_receipt=x)["status"], "HOLD_SIGNER_OUTSIDE_WINDOW")

    def test_signer_expired(self):
        self.add_r1()
        x = self.sign()
        signers = copy.deepcopy(self.signers)
        signers["LAB-KEY-01"]["not_after_utc"] = "2026-01-02T10:00:29Z"
        self.assertEqual(self.make_verifier(signers=signers).assess(**self.query, signed_receipt=x)["status"], "HOLD_SIGNER_OUTSIDE_WINDOW")

    def test_signed_time_future_of_decision_rejected(self):
        self.add_r1()
        x = self.sign(issued="2026-01-02T10:00:31Z")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_TIME_CLAIM_CONFLICT")

    def test_signed_time_before_local_availability_rejected(self):
        self.add_r1()
        x = self.sign(issued="2026-01-02T10:00:29Z")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_TIME_CLAIM_CONFLICT")

    def test_before_evidence_effective_gate(self):
        self.add_r1()
        query = {**self.query, "decision_at": "2026-01-02T10:00:29Z"}
        out = self.verifier.assess(**query, signed_receipt=None)
        self.assertEqual(out["status"], "HOLD_NO_VERSION_AT_DECISION")

    def test_cloud_denied_even_with_valid_signature(self):
        self.add_r1()
        x = self.sign()
        query = {**self.query, "requested_use": "CLOUD_PROCESSING"}
        self.assertEqual(self.verifier.assess(**query, signed_receipt=x)["status"], "HOLD_INVALID_USE")

    def test_model_training_denied_even_with_valid_signature(self):
        self.add_r1()
        x = self.sign()
        query = {**self.query, "requested_use": "MODEL_TRAINING"}
        self.assertEqual(self.verifier.assess(**query, signed_receipt=x)["status"], "HOLD_INVALID_USE")

    def test_vendor_data_denied_even_with_valid_signature(self):
        self.add_r1(rights="VENDOR_RESTRICTED")
        # Simulated envelope need not be well formed: governance must deny first.
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt={})["status"], "HOLD_RIGHTS_POLICY")

    def test_private_data_denied_even_with_valid_signature(self):
        self.add_r1(rights="OWNED_PRIVATE")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt={})["status"], "HOLD_RIGHTS_POLICY")

    def test_allowlist_empty_denied(self):
        self.add_r1()
        x = self.sign()
        self.assertEqual(self.make_verifier(ids=()).assess(**self.query, signed_receipt=x)["status"], "HOLD_FIXTURE_ORIGIN_UNVERIFIED")

    def test_future_revision_not_backported(self):
        self.add_r1()
        self.add_r2()
        x = self.sign()
        out = self.verifier.assess(**self.query, signed_receipt=x)
        self.assertEqual(out["status"], "SYNTHETIC_SIGNATURE_VALID_UNATTESTED")

    def test_asof_R2_receipt_binds_to_R2(self):
        self.add_r1()
        self.add_r2()
        query = {**self.query, "decision_at": self.D2}
        x = self.sign(query=query)
        out = self.verifier.assess(**query, signed_receipt=x)
        self.assertTrue(out["signature_valid"])

    def test_R1_receipt_cannot_bind_to_R2(self):
        self.add_r1()
        r1_receipt = self.sign()
        self.add_r2()
        query = {**self.query, "decision_at": self.D2}
        self.assertEqual(self.verifier.assess(**query, signed_receipt=r1_receipt)["status"], "HOLD_BINDING_MISMATCH")

    def test_replay_is_readonly(self):
        self.add_r1()
        x = self.sign()
        before = self.path.read_bytes()
        self.verifier.assess(**self.query, signed_receipt=x)
        self.assertEqual(before, self.path.read_bytes())

    def test_corrupted_ledger_denied_before_signature(self):
        self.add_r1()
        x = self.sign()
        self.path.write_text(self.path.read_text().replace('"revision_id":"R1"','"revision_id":"RX"'), encoding="utf-8")
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_LEDGER_INTEGRITY")

    def test_missing_ledger_denied_before_signature(self):
        out = self.verifier.assess(**self.query, signed_receipt={})
        self.assertEqual(out["status"], "HOLD_LEDGER_MISSING")

    def test_bad_signer_config_denied_on_init(self):
        config = copy.deepcopy(self.signers)
        config["LAB-KEY-01"]["usage"] = "COMMERCIAL_TRUSTED_TIME"
        with self.assertRaises(ValueError):
            self.make_verifier(signers=config)

    def test_bad_public_key_denied_on_init(self):
        config = copy.deepcopy(self.signers)
        config["LAB-KEY-01"]["public_key_b64"] = "a!b?"
        with self.assertRaises(ValueError):
            self.make_verifier(signers=config)

    def test_unsigned_envelope_is_rejected(self):
        self.add_r1()
        x = self.sign()
        del x["signature_b64"]
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_noncanonical_claim_timestamp_rejected(self):
        self.add_r1()
        x = self.sign()
        x["claims"]["claimed_signed_at_utc"] = "2026-01-02T21:00:30+11:00"
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_wrong_proof_kind_rejected(self):
        self.add_r1()
        x = self.sign()
        x["claims"]["proof_kind"] = "RFC3161_TRUSTED"
        self.assertEqual(self.verifier.assess(**self.query, signed_receipt=x)["status"], "HOLD_RECEIPT_FORMAT")

    def test_no_vendor_sdk_import(self):
        from kario_pit.attestation import signed_receipt
        module_text = Path(signed_receipt.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import lseg", module_text.lower())
        self.assertNotIn("import refinitiv", module_text.lower())
        self.assertNotIn("import finnhub", module_text.lower())


if __name__ == "__main__":
    unittest.main()
