"""KARIO v0.4B: ED25519 receipt signature laboratory, synthetic ONLY.

This is NOT RFC3161, a time-stamp authority, an attestation service, a
production trust store, legal clearance, or proof of historical existence.
The self-reported `claimed_signed_at_utc` is cryptographically authenticated
as a CLAIM, but its truth is NOT established by this signature. All paths
retain trusted_time_verified=False, external_attestation_verified=False,
pit_certified=False and rights_legally_cleared=False.

No vendor content, network traffic, API credentials, or signing private keys
are held in this verification module. The caller must provision its *lab*
public keys out of band. This module does not auto-trust keys in receipts.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime
from pathlib import Path

from kario_pit.audit.time_gate import parse_utc
from kario_pit.governance import GovernancePreflight
from kario_pit.replay import DecisionReplayer

RECEIPT_VERSION = "KARIO_SYNTHETIC_SIGNED_RECEIPT_V0.4B"
PROOF_KIND = "SYNTHETIC_LAB_ED25519"
VERIFIER_VERSION = "KARIO_SIGNATURE_LAB_VERIFIER_V0.4B"
CLAIM_FIELDS = frozenset({
    "proof_kind", "evidence_id", "revision_id", "entry_hash",
    "content_sha256", "provider_id", "source_record_id",
    "decision_at_utc", "effective_available_at_utc", "claimed_signed_at_utc",
})
_RECEIPT_FIELDS = frozenset({"schema_version", "key_id", "claims", "signature_b64"})
_KEY_FIELDS = frozenset({
    "public_key_b64", "usage", "not_before_utc", "not_after_utc", "revoked",
})
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = b"KARIO_SIGNED_RECEIPT_LAB_V0.4B\x00"


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _strict_b64(s: object, size: int) -> bytes:
    if not isinstance(s, str) or len(s) > 128:
        raise ValueError("invalid base64 encoding")
    try:
        decoded = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error) as e:
        raise ValueError("invalid base64 encoding") from e
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != s:
        raise ValueError("noncanonical or invalid key/signature size")
    return decoded


def signing_message(unsigned_envelope: dict) -> bytes:
    """Create deterministic domain-separated signed bytes.

    This helper is solely for interoperability of synthetic test fixtures.
    It does NOT certify the authenticity of signer-supplied clock claims.
    """
    if not isinstance(unsigned_envelope, dict) or set(unsigned_envelope) != {
        "schema_version", "key_id", "claims",
    }:
        raise ValueError("bad unsigned envelope fields")
    if unsigned_envelope["schema_version"] != RECEIPT_VERSION:
        raise ValueError("unsupported signed receipt version")
    key_id = unsigned_envelope["key_id"]
    claims = unsigned_envelope["claims"]
    if not isinstance(key_id, str) or not _ID_RE.fullmatch(key_id):
        raise ValueError("invalid key identifier")
    if not isinstance(claims, dict) or set(claims) != CLAIM_FIELDS:
        raise ValueError("bad claims fields")
    for name, val in claims.items():
        if not isinstance(val, str) or len(val) > 128:
            raise ValueError("invalid claims value: " + name)
    if claims["proof_kind"] != PROOF_KIND:
        raise ValueError("not a synthetic lab proof")
    for name in ("evidence_id", "revision_id", "provider_id", "source_record_id"):
        if not _ID_RE.fullmatch(claims[name]):
            raise ValueError("invalid identifier: " + name)
    for name in ("entry_hash", "content_sha256"):
        if not _SHA_RE.fullmatch(claims[name]):
            raise ValueError("invalid hash: " + name)
    for name in ("decision_at_utc", "effective_available_at_utc", "claimed_signed_at_utc"):
        raw = claims[name]
        if _iso(parse_utc(raw)) != raw:
            raise ValueError("noncanonical timestamp: " + name)
    canonical = json.dumps(
        unsigned_envelope, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return _DOMAIN + canonical


class SignedReceiptLabVerifier:
    """Read-only proof-verification *lab* layered on v0.4 preflight.

    The caller-supplied key map is never inferred from envelope contents.
    It is SYNTHETIC_LAB_ONLY and cannot be elevated into a production authority.
    """

    def __init__(
        self,
        ledger_path: str | Path,
        *,
        synthetic_fixture_ids=(),
        lab_signers: dict | None = None,
    ):
        self._gov = GovernancePreflight(
            ledger_path, synthetic_fixture_ids=synthetic_fixture_ids,
        )
        self._replayer = DecisionReplayer(ledger_path)
        if lab_signers is None:
            lab_signers = {}
        if not isinstance(lab_signers, dict):
            raise ValueError("signer configuration must be a dict")
        validated = {}
        for signer_id, config in lab_signers.items():
            if not isinstance(signer_id, str) or not _ID_RE.fullmatch(signer_id):
                raise ValueError("invalid signer id")
            if not isinstance(config, dict) or set(config) != _KEY_FIELDS:
                raise ValueError("invalid lab signer configuration")
            _strict_b64(config["public_key_b64"], 32)
            if config["usage"] != "SYNTHETIC_LAB_ONLY" or type(config["revoked"]) is not bool:
                raise ValueError("only synthetic lab keys are permitted")
            start = parse_utc(config["not_before_utc"])
            end = parse_utc(config["not_after_utc"])
            if end <= start:
                raise ValueError("invalid signer validity window")
            validated[signer_id] = dict(config)
        self._signers = validated

    def assess(
        self,
        *,
        provider_id: str,
        source_record_id: str,
        decision_at: str,
        requested_use: str,
        signed_receipt: dict | None,
    ) -> dict:
        """Never raises positive PIT status, including with a valid signature."""
        result = {
            "schema_version": VERIFIER_VERSION,
            "status": "HOLD_PREFLIGHT",
            "signature_valid": False,
            "binding_verified": False,
            "signed_clock_claim_consistent": False,
            "synthetic_demo_policy_pass": False,
            "trusted_time_verified": False,
            "external_attestation_verified": False,
            "independent_provenance_verified": False,
            "rights_legally_cleared": False,
            "pit_certified": False,
        }
        preflight = self._gov.assess(
            provider_id=provider_id,
            source_record_id=source_record_id,
            decision_at=decision_at,
            requested_use=requested_use,
        )
        if not preflight["synthetic_demo_policy_pass"]:
            result["status"] = preflight["status"]
            return result
        # Need the record's canonical SHA256 and entry hash, which the v0.4
        # projection intentionally does not expose; read via verified v0.3.
        replay = self._replayer.replay_document(
            provider_id=provider_id,
            source_record_id=source_record_id,
            decision_at=decision_at,
        )
        if (
            replay["status"] != "TIME_GATE_PASS_UNVERIFIED"
            or not replay["registry_integrity_verified"]
            or replay["selected_evidence_id"] != preflight["selected_evidence_id"]
            or replay["selected_revision_id"] != preflight["selected_revision_id"]
        ):
            result["status"] = "HOLD_REPLAY_CHANGED"
            return result
        if signed_receipt is None:
            result["status"] = "HOLD_RECEIPT_MISSING"
            return result
        if not isinstance(signed_receipt, dict) or set(signed_receipt) != _RECEIPT_FIELDS:
            result["status"] = "HOLD_RECEIPT_FORMAT"
            return result
        unsigned = {k: signed_receipt[k] for k in (
            "schema_version", "key_id", "claims",
        )}
        try:
            signed_bytes = signing_message(unsigned)
            signature = _strict_b64(signed_receipt["signature_b64"], 64)
        except (ValueError, TypeError, OverflowError):
            result["status"] = "HOLD_RECEIPT_FORMAT"
            return result
        claims = unsigned["claims"]
        # Require every bound field (including decision context) to match.
        expected = {
            "proof_kind": PROOF_KIND,
            "evidence_id": replay["selected_evidence_id"],
            "revision_id": replay["selected_revision_id"],
            "entry_hash": replay["selected_entry_hash"],
            "content_sha256": replay["selected_content_sha256"],
            "provider_id": provider_id,
            "source_record_id": source_record_id,
            "decision_at_utc": replay["decision_at_utc"],
            "effective_available_at_utc": replay["selected_available_at_utc"],
        }
        if any(claims[key] != value for key, value in expected.items()):
            result["status"] = "HOLD_BINDING_MISMATCH"
            return result
        result["binding_verified"] = True
        issued = parse_utc(claims["claimed_signed_at_utc"])
        start = parse_utc(replay["selected_available_at_utc"])
        decision = parse_utc(replay["decision_at_utc"])
        if not start <= issued <= decision:
            result["status"] = "HOLD_TIME_CLAIM_CONFLICT"
            return result
        result["signed_clock_claim_consistent"] = True
        key_id = unsigned["key_id"]
        key_config = self._signers.get(key_id)
        if key_config is None:
            result["status"] = "HOLD_UNKNOWN_SIGNER"
            return result
        # This is a conservative, static revocation flag. A robust trusted
        # system needs independently sourced, historical revocation evidence.
        if key_config["revoked"]:
            result["status"] = "HOLD_SIGNER_REVOKED"
            return result
        if not (
            parse_utc(key_config["not_before_utc"])
            <= issued <= parse_utc(key_config["not_after_utc"])
        ):
            result["status"] = "HOLD_SIGNER_OUTSIDE_WINDOW"
            return result
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            result["status"] = "HOLD_CRYPTO_UNAVAILABLE"
            return result
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                _strict_b64(key_config["public_key_b64"], 32)
            )
            public_key.verify(signature, signed_bytes)
        except (InvalidSignature, ValueError, TypeError):
            result["status"] = "HOLD_SIGNATURE_INVALID"
            return result
        result.update({
            "status": "SYNTHETIC_SIGNATURE_VALID_UNATTESTED",
            "signature_valid": True,
            "synthetic_demo_policy_pass": True,
        })
        return result
