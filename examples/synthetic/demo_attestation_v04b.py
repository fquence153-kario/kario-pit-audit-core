"""Local synthetic signed receipt demonstration; no TSA or third-party time proof."""
import argparse
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kario_pit.attestation import RECEIPT_VERSION, SignedReceiptLabVerifier, signing_message
from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description="KARIO synthetic signature lab")
    parser.add_argument("--ledger", required=True, help="Nonexistent synthetic ledger path")
    args = parser.parse_args()
    path = Path(args.ledger)
    if path.exists() or path.is_symlink():
        parser.error("Refusing to overwrite existing ledger")

    signer_private = Ed25519PrivateKey.generate()  # in-memory lab ONLY
    signer_public_b64 = base64.b64encode(
        signer_private.public_key().public_bytes_raw()
    ).decode("ascii")
    now = datetime.now(timezone.utc)
    ledger = EvidenceLedger(path)
    row = ledger.append(
        evidence_id="SYN-SIGNED-01", provider_id="MOCK",
        source_record_id="SIGNED-DEMO", revision_id="R1",
        rights_class="SYNTHETIC_PUBLIC",
        content=b"SYNTHETIC_ONLY_NO_VENDOR_CONTENT",
        registered_latency_seconds=30,
        source_published_at=iso(now - timedelta(seconds=60)),
    )
    recorded = datetime.fromisoformat(row["recorded_at_utc"].replace("Z", "+00:00"))
    decision = iso(recorded + timedelta(seconds=30))
    replay = DecisionReplayer(path).replay_document(
        provider_id="MOCK", source_record_id="SIGNED-DEMO", decision_at=decision,
    )
    if replay["status"] != "TIME_GATE_PASS_UNVERIFIED":
        raise RuntimeError("Synthetic replay did not pass the local time gate")

    claims = {
        "proof_kind": "SYNTHETIC_LAB_ED25519",
        "evidence_id": replay["selected_evidence_id"],
        "revision_id": replay["selected_revision_id"],
        "entry_hash": replay["selected_entry_hash"],
        "content_sha256": replay["selected_content_sha256"],
        "provider_id": "MOCK", "source_record_id": "SIGNED-DEMO",
        "decision_at_utc": replay["decision_at_utc"],
        "effective_available_at_utc": replay["selected_available_at_utc"],
        "claimed_signed_at_utc": decision,
    }
    unsigned = {
        "schema_version": RECEIPT_VERSION,
        "key_id": "EPHEMERAL-LAB-KEY",
        "claims": claims,
    }
    receipt = {
        **unsigned,
        "signature_b64": base64.b64encode(
            signer_private.sign(signing_message(unsigned))
        ).decode("ascii"),
    }
    key_config = {
        "public_key_b64": signer_public_b64,
        "usage": "SYNTHETIC_LAB_ONLY",
        "not_before_utc": iso(recorded - timedelta(days=1)),
        "not_after_utc": iso(recorded + timedelta(days=1)),
        "revoked": False,
    }
    verifier = SignedReceiptLabVerifier(
        path, synthetic_fixture_ids={"SYN-SIGNED-01"},
        lab_signers={"EPHEMERAL-LAB-KEY": key_config},
    )
    query = dict(provider_id="MOCK", source_record_id="SIGNED-DEMO",
                 decision_at=decision, requested_use="LOCAL_SYNTHETIC_TEST")
    ok = verifier.assess(**query, signed_receipt=receipt)
    altered = json.loads(json.dumps(receipt))
    altered["claims"]["claimed_signed_at_utc"] = iso(recorded + timedelta(seconds=29))
    corrupted = verifier.assess(**query, signed_receipt=altered)
    revoked_verifier = SignedReceiptLabVerifier(
        path, synthetic_fixture_ids={"SYN-SIGNED-01"},
        lab_signers={"EPHEMERAL-LAB-KEY": {**key_config, "revoked": True}},
    )
    revoked = revoked_verifier.assess(**query, signed_receipt=receipt)
    denied = verifier.assess(**{**query, "requested_use": "CLOUD_PROCESSING"}, signed_receipt=receipt)
    print(json.dumps({
        "synthetic_ledger": str(path),
        "ledger_verification": ledger.verify(),
        "signature_lab_valid": ok,
        "altered_claim_denied": corrupted,
        "revoked_signer_denied": revoked,
        "cloud_use_denied": denied,
        "notice": "SIGNATURE VALIDITY DOES NOT PROVE INDEPENDENT TIME, PIT, OR DATA RIGHTS",
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
