"""KARIO v0.7 offline PRIVATE-LOCAL time-gate pilot.

Threat boundary:
- Operator-declared OWNED_PRIVATE does NOT prove ownership or legal rights.
- Ledger must contain *only* OWNED_PRIVATE records, and be outside code tree.
- Requires explicit right-to-process acknowledgment, a SHA-256 ledger pin, and
  declared LOCAL_PRIVATE_AUDIT purpose. No vendor data authorization, network,
  cloud processing, model training, publishing, or public-facing export.
- Default result REDACTS identifiers, revision IDs, content hashes and head hash.
  Local detailed results require a second explicit acknowledgment, and should
  never be placed into public logs or repositories.
- Local ingestion timestamps and hash chains are not independently attested.
- This does not change v0.3's synthetic-public DecisionReplayer policy.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from pathlib import Path
import re

from kario_pit.audit.time_gate import parse_utc, audit_time_gate
from kario_pit.registry import EvidenceLedger, LedgerIntegrityError
from kario_pit.intake.vendor_neutral_v06 import PROJECT_ROOT

SCHEMA_VERSION = "KARIO_LOCAL_PRIVATE_AUDIT_V0.7"
PROOF_CLASS = "LOCAL_INGEST_RECEIPT_UNATTESTED"
LOCAL_USE = "LOCAL_PRIVATE_AUDIT"
RIGHTS_CLASS = "OWNED_PRIVATE"
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_LEDGER_BYTES = 32 * 1024 * 1024


def _utc(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _file_sha256(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        while (block := f.read(1024 * 1024)):
            h.update(block)
    return h.hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


class PrivateLocalAuditor:
    """Read-only, fail-closed audit of a single private-only local ledger.

    Manual rights acknowledgement is necessary but NOT evidence of rights.
    Default output is deliberately non-identifying. Not multi-tenant isolation.
    """
    def __init__(self, ledger_path: str | Path):
        self.path = Path(ledger_path)

    def audit_document(
        self,
        *,
        provider_id: str,
        source_record_id: str,
        decision_at: str,
        expected_ledger_sha256: str,
        acknowledge_local_rights: bool = False,
        requested_use: str = LOCAL_USE,
        detail_level: str = "REDACTED",
        acknowledge_private_detail: bool = False,
    ) -> dict:
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "HOLD_INVALID_QUERY",
            "time_gate_pass": False,
            "private_version_selected": False,
            "registry_integrity_verified": False,
            "private_details_redacted": True,
            "evidence_proof_class": PROOF_CLASS,
            "rights_source": "OPERATOR_DECLARED_NOT_VERIFIED",
            "rights_legally_cleared": False,
            "source_time_independently_verified": False,
            "trusted_time_verified": False,
            "pit_certified": False,
            "external_export_authorized": False,
            "model_training_authorized": False,
            "production_ready": False,
        }

        if (
            requested_use != LOCAL_USE or type(acknowledge_local_rights) is not bool
            or type(acknowledge_private_detail) is not bool
            or detail_level not in ("REDACTED", "LOCAL_FULL")
            or not isinstance(detail_level, str)
        ):
            result["status"] = "HOLD_INVALID_USE"
            return result
        if acknowledge_local_rights is not True:
            result["status"] = "HOLD_RIGHTS_ACK_REQUIRED"
            return result
        if detail_level == "LOCAL_FULL" and acknowledge_private_detail is not True:
            result["status"] = "HOLD_PRIVATE_DETAIL_ACK_REQUIRED"
            return result
        if not (
            isinstance(provider_id, str) and _ID_RE.fullmatch(provider_id)
            and isinstance(source_record_id, str) and _ID_RE.fullmatch(source_record_id)
        ):
            return result
        if not isinstance(expected_ledger_sha256, str) or not _SHA_RE.fullmatch(expected_ledger_sha256):
            result["status"] = "HOLD_LEDGER_PIN_INVALID"
            return result
        try:
            decision = parse_utc(decision_at)
        except (ValueError, TypeError, OverflowError):
            result["status"] = "HOLD_INVALID_DECISION_TIME"
            return result

        # A symlink in any path component is disallowed for the single-user lab.
        try:
            if any(p.is_symlink() for p in (self.path, *self.path.parents)):
                result["status"] = "HOLD_UNSAFE_LEDGER_PATH"
                return result
            if _inside(self.path, PROJECT_ROOT):
                result["status"] = "HOLD_LEDGER_INSIDE_SOURCE_TREE"
                return result
            if not self.path.is_file():
                result["status"] = "HOLD_LEDGER_MISSING"
                return result
            if self.path.stat().st_size > _MAX_LEDGER_BYTES:
                result["status"] = "HOLD_LEDGER_INTEGRITY"
                return result
            digest_before = _file_sha256(self.path)
            if digest_before != expected_ledger_sha256:
                result["status"] = "HOLD_LEDGER_PIN_MISMATCH"
                return result
            rows = EvidenceLedger(self.path)._verify_and_load()
            digest_after = _file_sha256(self.path)
            if digest_before != digest_after:
                result["status"] = "HOLD_LEDGER_CHANGED_DURING_AUDIT"
                return result
        except (LedgerIntegrityError, OSError, ValueError, TypeError):
            result["status"] = "HOLD_LEDGER_INTEGRITY"
            return result

        # The v0.7 single-scope prototype must be an exclusively private ledger.
        # No synthetic or restricted-vendor rows, including unrelated/future rows.
        if not rows or any(r["payload"]["rights_class"] != RIGHTS_CLASS for r in rows):
            result["status"] = "HOLD_LEDGER_NOT_PRIVATE_ONLY"
            return result

        previous_receipt = None
        for row in rows:
            try:
                receipt = parse_utc(row["recorded_at_utc"])
            except (ValueError, TypeError, OverflowError):
                result["status"] = "HOLD_LEDGER_INTEGRITY"
                return result
            if previous_receipt is not None and receipt < previous_receipt:
                result["status"] = "HOLD_LEDGER_CLOCK_REGRESSION"
                return result
            previous_receipt = receipt

        result["registry_integrity_verified"] = True
        matching = [r for r in rows if r["payload"]["provider_id"] == provider_id
                    and r["payload"]["source_record_id"] == source_record_id]
        if not matching:
            result["status"] = "HOLD_SOURCE_NOT_FOUND"
            return result

        asof = [r for r in matching
                if parse_utc(r["payload"]["observed_at_utc"]) <= decision]
        if not asof:
            result["status"] = "HOLD_NO_VERSION_AT_DECISION"
            return result

        last_published = None
        eligible = []
        for row in asof:
            p = row["payload"]
            if p["source_published_at_utc"] is None:
                result["status"] = "HOLD_SOURCE_TIME_MISSING"
                return result
            published = parse_utc(p["source_published_at_utc"])
            observed = parse_utc(p["observed_at_utc"])
            if published > observed:
                result["status"] = "HOLD_CHRONOLOGY_CONFLICT"
                return result
            if last_published is not None and published < last_published:
                result["status"] = "HOLD_REVISION_TIME_REGRESSION"
                return result
            last_published = published
            gate = audit_time_gate(
                evidence_id=p["evidence_id"],
                decision_at=_utc(decision),
                availability_upper_at=p["availability_upper_at_utc"],
                registered_latency_seconds=p["registered_latency_seconds"],
                source_published_at=p["source_published_at_utc"],
            )
            if gate["status"] == "TIME_GATE_PASS_UNVERIFIED":
                eligible.append((row, gate))
            elif gate["status"] != "HOLD_AFTER_DECISION":
                result["status"] = "HOLD_REPLAY_TIME_POLICY"
                return result
        if not eligible:
            result["status"] = "HOLD_NO_VERSION_EFFECTIVE_AT_DECISION"
            return result

        chosen, gate = eligible[-1]
        result.update({
            "status": "LOCAL_PRIVATE_TIME_GATE_PASS_UNATTESTED",
            "time_gate_pass": True,
            "private_version_selected": True,
        })
        # Only caller who explicitly opts into local private detail gets IDs.
        if detail_level == "LOCAL_FULL":
            p = chosen["payload"]
            result.update({
                "private_details_redacted": False,
                "selected_evidence_id": p["evidence_id"],
                "selected_revision_id": p["revision_id"],
                "selected_content_sha256": p["content_sha256"],
                "selected_entry_hash": chosen["entry_hash"],
                "effective_available_at_utc": gate["effective_available_at_utc"],
            })
        return result
