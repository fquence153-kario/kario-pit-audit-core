"""Synthetic-public historical decision replay (KARIO v0.3 pilot).

Rules:
* Replays a single document using *only* revisions effective at the requested
  decision timestamp; revisions appended in the future cannot alter the result.
* Full v0.2 hash-chain verification is mandatory. Regressing local receipt
  clocks and known chronology inconsistencies cause HOLD, not selection.
* Only operator-labelled SYNTHETIC_PUBLIC evidence can be emitted by this
  prototype; this tag is NOT independently verified redistribution permission.
* A successful replay is a LOCAL, UNATTESTED time comparison, never a proof of
  historical data availability or an independently PIT-certified event.
* No LSEG SDK, vendor content, external API, network or model dependency.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re

from kario_pit.audit.time_gate import audit_time_gate, parse_utc
from kario_pit.registry import EvidenceLedger, LedgerIntegrityError

SCHEMA_VERSION = "KARIO_DECISION_REPLAY_V0.3"
PROOF_CLASS = "LOCAL_INGEST_RECEIPT_UNATTESTED"
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PUBLIC_RIGHTS_CLASS = "SYNTHETIC_PUBLIC"


def _format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class DecisionReplayer:
    """Read-only replay against the v0.2 metadata ledger.

    This pinned v0.3 bridge uses v0.2's internal _verify_and_load() because v0.2
    did not expose a verified-entries public API. It performs NO writes.
    """

    def __init__(self, ledger_path: str | Path):
        self.ledger = EvidenceLedger(ledger_path)

    def replay_document(
        self,
        *,
        provider_id: str,
        source_record_id: str,
        decision_at: str,
    ) -> dict:
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "HOLD_INVALID_QUERY",
            "time_gate_pass": False,
            "pit_certified": False,
            "registry_integrity_verified": False,
            "evidence_proof_class": PROOF_CLASS,
            "decision_at_utc": None,
            "selected_evidence_id": None,
            "selected_revision_id": None,
        }

        # Inputs must be deliberate identifiers. Avoid fuzzy matching or
        # undocumented search fallback for historical replay.
        if not all(
            isinstance(value, str) and _ID_RE.fullmatch(value)
            for value in (provider_id, source_record_id)
        ):
            return result

        try:
            decision = parse_utc(decision_at)
        except (ValueError, TypeError, OverflowError):
            result["status"] = "HOLD_INVALID_DECISION_AT"
            return result

        result["decision_at_utc"] = _format_utc(decision)

        try:
            # A missing file is never mistaken for a verified empty database.
            if not self.ledger.path.exists() and not self.ledger.path.is_symlink():
                result["status"] = "HOLD_LEDGER_MISSING"
                return result
            verified_rows = self.ledger._verify_and_load()
        except (LedgerIntegrityError, OSError):
            result["status"] = "HOLD_LEDGER_INTEGRITY"
            return result

        # Stronger condition than v0.2: a local clock moving backwards during
        # appends invalidates ALL replay in this pilot, instead of permitting
        # an accidentally backdated evidence receipt.
        last_receipt = None
        for row in verified_rows:
            receipt = parse_utc(row["recorded_at_utc"])
            if last_receipt is not None and receipt < last_receipt:
                result["status"] = "HOLD_LEDGER_CLOCK_REGRESSION"
                return result
            last_receipt = receipt

        result["registry_integrity_verified"] = True
        matching = [
            row for row in verified_rows
            if row["payload"]["provider_id"] == provider_id
            and row["payload"]["source_record_id"] == source_record_id
        ]
        if not matching:
            result["status"] = "HOLD_SOURCE_NOT_FOUND"
            return result

        # Critically, do not inspect rights, source times, or versions first
        # observed AFTER decision_at. This preserves strict as-of semantics.
        observed_asof = [
            row for row in matching
            if parse_utc(row["payload"]["observed_at_utc"]) <= decision
        ]
        if not observed_asof:
            result["status"] = "HOLD_NO_VERSION_AT_DECISION"
            return result

        # Rights are conservatively enforced across all versions OBSERVED
        # by T. This public prototype never emits private/vendor metadata.
        # rights_class is operator-declared and must never be treated as legal
        # clearance: use ONLY deliberately synthetic demo material here.
        if any(
            row["payload"]["rights_class"] != _PUBLIC_RIGHTS_CLASS
            for row in observed_asof
        ):
            result["status"] = "HOLD_RIGHTS_POLICY"
            return result

        if any(
            row["payload"]["source_published_at_utc"] is None
            for row in observed_asof
        ):
            result["status"] = "HOLD_SOURCE_TIME_MISSING"
            return result

        # Fail closed on impossible source chronology even when latency has
        # not yet elapsed. Do not silently skip an invalid early version.
        for row in observed_asof:
            payload = row["payload"]
            if parse_utc(payload["source_published_at_utc"]) > parse_utc(
                payload["observed_at_utc"]
            ):
                result["status"] = "HOLD_CHRONOLOGY_CONFLICT"
                return result

        eligible = []
        for row in observed_asof:
            payload = row["payload"]
            gate = audit_time_gate(
                evidence_id=payload["evidence_id"],
                decision_at=result["decision_at_utc"],
                availability_upper_at=payload["availability_upper_at_utc"],
                registered_latency_seconds=payload["registered_latency_seconds"],
                source_published_at=payload["source_published_at_utc"],
            )
            if gate["status"] == "TIME_GATE_PASS_UNVERIFIED":
                eligible.append((row, gate))
            elif gate["status"] != "HOLD_AFTER_DECISION":
                result["status"] = "HOLD_REPLAY_TIME_POLICY"
                return result

        if not eligible:
            result["status"] = "HOLD_NO_VERSION_AT_DECISION"
            return result

        # v0.2 requires a linear revision chain: latest eligible append is
        # the latest evidence revision that was usable AT decision time.
        # Do not return counts, current head hash or any later version fields:
        # those would introduce future-derived audit metadata into a snapshot.
        selected, gate = eligible[-1]
        payload = selected["payload"]
        result.update({
            "status": "TIME_GATE_PASS_UNVERIFIED",
            "time_gate_pass": True,
            "selected_evidence_id": payload["evidence_id"],
            "selected_revision_id": payload["revision_id"],
            "selected_content_sha256": payload["content_sha256"],
            "selected_entry_hash": selected["entry_hash"],
            "selected_available_at_utc": gate["effective_available_at_utc"],
            "selected_source_published_at_utc": payload["source_published_at_utc"],
            "rights_class": payload["rights_class"],
            "selection_rule": "LATEST_ELIGIBLE_REVISION_IN_VERIFIED_APPEND_ORDER",
        })
        return result
