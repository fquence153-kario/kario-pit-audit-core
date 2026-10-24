"""KARIO v0.4: fail-closed *preflight*, NOT a certified PIT trust engine.

Design constraints:
- Only synthetic fixtures explicitly listed by the caller are ever eligible.
- v0.3 remains the as-of decision authority; do not re-select revisions here.
- Vendor, private, cloud, model-training and unknown uses are not authorized.
- Source claims are operator assertions, not externally validated evidence.
- An unsigned/local assertion cannot prove independent provenance or time.
- Even a PASS leaves pit_certified=False, attestation_verified=False.
- No network, vendor SDK, model API, storage writes or external packages.

IMPORTANT: Adding a fixture ID is *not* legal clearance for real data. It is
solely a test harness control. NEVER apply to a vendor or mixed dataset.
"""
from __future__ import annotations

from pathlib import Path
import re

from kario_pit.audit.time_gate import parse_utc
from kario_pit.replay import DecisionReplayer

SCHEMA_VERSION = "KARIO_GOVERNANCE_PREFLIGHT_V0.4"
ASSERTION_VERSION = "KARIO_LOCAL_SOURCE_ASSERTION_V0.4"
ALLOWED_USES = frozenset({"LOCAL_SYNTHETIC_TEST", "PUBLIC_SYNTHETIC_DEMO"})
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ASSERTION_FIELDS = frozenset({
    "schema_version", "evidence_id", "entry_hash", "asserted_at_utc",
    "assertion_kind",
})


def _inspect_local_assertion(assertion: object, *, replay: dict) -> str:
    """Validate an operator claim's shape/bindings without trusting its time."""
    if assertion is None:
        return "MISSING"
    if not isinstance(assertion, dict) or set(assertion) != _ASSERTION_FIELDS:
        return "INVALID_FORMAT"
    if (
        assertion.get("schema_version") != ASSERTION_VERSION
        or assertion.get("assertion_kind") != "LOCAL_OPERATOR_DECLARATION"
    ):
        return "UNSUPPORTED_ASSERTION"
    if (
        not isinstance(assertion.get("evidence_id"), str)
        or not _ID_RE.fullmatch(assertion["evidence_id"])
        or not isinstance(assertion.get("entry_hash"), str)
        or not _HEX64_RE.fullmatch(assertion["entry_hash"])
    ):
        return "INVALID_FORMAT"
    if (
        assertion["evidence_id"] != replay["selected_evidence_id"]
        or assertion["entry_hash"] != replay["selected_entry_hash"]
    ):
        return "BINDING_MISMATCH"
    try:
        asserted_at = parse_utc(assertion.get("asserted_at_utc"))
        decision_at = parse_utc(replay["decision_at_utc"])
    except (TypeError, ValueError, OverflowError):
        return "INVALID_TIMESTAMP"
    if asserted_at > decision_at:
        return "FUTURE_ASSERTION_AT_DECISION"
    # Shape, linkage and relative timestamp are not independent proof.
    return "LOCAL_ASSERTION_MATCHED_UNVERIFIED"


class GovernancePreflight:
    """Read-only LSEG-free governance layer over v0.3 decision replay.

    `synthetic_fixture_ids` is an explicit TEST fixture allowlist, and MUST
    NOT be populated from untrusted inputs or real licensed vendor records.
    """

    def __init__(self, ledger_path: str | Path, *, synthetic_fixture_ids=()):
        ids = list(synthetic_fixture_ids)
        if not all(isinstance(x, str) and _ID_RE.fullmatch(x) for x in ids):
            raise ValueError("Invalid synthetic fixture identifier")
        self._fixture_ids = frozenset(ids)
        self._replayer = DecisionReplayer(ledger_path)

    def assess(
        self,
        *,
        provider_id: str,
        source_record_id: str,
        decision_at: str,
        requested_use: str,
        source_assertion: dict | None = None,
    ) -> dict:
        """Evaluate a public/local *synthetic* demo; never issue PIT certificates."""
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "HOLD_INVALID_USE",
            "requested_use": (requested_use if isinstance(requested_use, str) and requested_use in ALLOWED_USES else None),
            "time_gate_pass": False,
            "synthetic_demo_policy_pass": False,
            "pit_certified": False,
            "registry_integrity_verified": False,
            "independent_provenance_verified": False,
            "external_attestation_verified": False,
            "rights_legally_cleared": False,
            "attestation_status": "NOT_EVALUATED",
            "selected_evidence_id": None,
            "selected_revision_id": None,
            "evidence_proof_class": "LOCAL_RECEIPT_UNATTESTED",
        }
        if not isinstance(requested_use, str) or requested_use not in ALLOWED_USES:
            return result

        replay = self._replayer.replay_document(
            provider_id=provider_id,
            source_record_id=source_record_id,
            decision_at=decision_at,
        )
        result["registry_integrity_verified"] = bool(
            replay.get("registry_integrity_verified")
        )
        if replay.get("status") != "TIME_GATE_PASS_UNVERIFIED":
            # Fail closed. Do not leak evidence IDs, hashes, revisions, or
            # private/vendor metadata when the underlying gate failed.
            result["status"] = replay.get("status", "HOLD_REPLAY_UNAVAILABLE")
            return result

        result["time_gate_pass"] = True
        if (
            replay.get("rights_class") != "SYNTHETIC_PUBLIC"
            or replay.get("selected_evidence_id") not in self._fixture_ids
        ):
            result["status"] = "HOLD_FIXTURE_ORIGIN_UNVERIFIED"
            return result

        attestation_status = _inspect_local_assertion(source_assertion, replay=replay)
        result["attestation_status"] = attestation_status
        if attestation_status not in {
            "MISSING", "LOCAL_ASSERTION_MATCHED_UNVERIFIED",
        }:
            result["status"] = "HOLD_SOURCE_ASSERTION"
            return result

        result.update({
            "status": "SYNTHETIC_PREFLIGHT_PASS_UNATTESTED",
            "synthetic_demo_policy_pass": True,
            "selected_evidence_id": replay["selected_evidence_id"],
            "selected_revision_id": replay["selected_revision_id"],
            "decision_at_utc": replay["decision_at_utc"],
            "local_time_gate_effective_at_utc": replay["selected_available_at_utc"],
        })
        return result
