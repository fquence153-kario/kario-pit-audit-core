"""Evidence Ledger v0.2: local metadata-only append log.

Security / evidence boundaries:
* SHA-256 covers content bytes supplied to append(); raw bytes are never stored.
* Local wall-clock receipts do NOT independently prove historical availability.
* The hash chain detects un-recomputed edits; it is not authenticated or anchored.
* One writer at a time via an exclusive lock-file. This is a pilot, NOT a DB.
* No LSEG or other provider SDK imported; no network calls.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator
import json
import os
import re

from kario_pit.audit.time_gate import audit_time_gate, parse_utc

SCHEMA_VERSION = "KARIO_EVIDENCE_V0.2"
GENESIS_HASH = "0" * 64
TIME_BASIS = "LOCAL_INGEST_RECEIPT_UNATTESTED"
RIGHTS_CLASSES = frozenset({"SYNTHETIC_PUBLIC", "OWNED_PRIVATE", "VENDOR_RESTRICTED"})
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_LEDGER_BYTES = 32 * 1024 * 1024
_MAX_LINE_BYTES = 64 * 1024
_MAX_CONTENT_BYTES = 16 * 1024 * 1024
_PAYLOAD_FIELDS = frozenset({
    "schema_version", "evidence_id", "provider_id", "source_record_id",
    "revision_id", "supersedes_evidence_id", "source_published_at_utc",
    "observed_at_utc", "availability_upper_at_utc",
    "registered_latency_seconds", "content_sha256", "rights_class",
    "time_basis", "raw_content_stored",
})


class RegistryValidationError(ValueError):
    """A new entry fails the versioned evidence input contract."""


class DuplicateEvidenceError(RegistryValidationError):
    """Reusing an evidence ID or revision ID is not allowed."""


class LedgerIntegrityError(RuntimeError):
    """An existing ledger cannot be safely read or extended."""


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(obj: Any) -> str:
    return sha256(_canonical(obj)).hexdigest()


def _required_id(name: str, value: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise RegistryValidationError(
            f"{name} must contain 1-128 characters from [A-Za-z0-9._:-]"
        )
    return value


def _optional_timestamp(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return parse_utc(value).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError) as exc:
        raise RegistryValidationError(f"Invalid {name}: {exc}") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _validate_payload(p: Any) -> None:
    if not isinstance(p, dict) or frozenset(p) != _PAYLOAD_FIELDS:
        raise RegistryValidationError("Unexpected payload fields or missing payload fields")
    if p["schema_version"] != SCHEMA_VERSION:
        raise RegistryValidationError("Unsupported evidence schema")
    for key in ("evidence_id", "provider_id", "source_record_id", "revision_id"):
        _required_id(key, p[key])
    if p["supersedes_evidence_id"] is not None:
        _required_id("supersedes_evidence_id", p["supersedes_evidence_id"])
    if p["rights_class"] not in RIGHTS_CLASSES:
        raise RegistryValidationError("Unrecognized rights_class")
    if p["time_basis"] != TIME_BASIS or p["raw_content_stored"] is not False:
        raise RegistryValidationError("Invalid time basis or content storage flag")
    if not isinstance(p["content_sha256"], str) or not _SHA_RE.fullmatch(p["content_sha256"]):
        raise RegistryValidationError("Invalid content_sha256")
    if type(p["registered_latency_seconds"]) is not int or p["registered_latency_seconds"] < 0:
        raise RegistryValidationError("Latency must be a non-negative integer")
    # Canonical UTC required on persisted timestamps. This also catches naive times.
    for key in ("observed_at_utc", "availability_upper_at_utc"):
        if _optional_timestamp(key, p[key]) != p[key]:
            raise RegistryValidationError(f"Noncanonical timestamp: {key}")
    published = p["source_published_at_utc"]
    if published is not None and _optional_timestamp("source_published_at_utc", published) != published:
        raise RegistryValidationError("Noncanonical source timestamp")
    if p["availability_upper_at_utc"] != p["observed_at_utc"]:
        raise RegistryValidationError("v0.2 uses only local ingestion as availability upper bound")


def _validate_revision(p: dict, seen: list[dict]) -> None:
    eid = p["evidence_id"]
    if any(r["evidence_id"] == eid for r in seen):
        raise DuplicateEvidenceError(f"Duplicate evidence_id: {eid}")
    previous = [
        r for r in seen
        if r["provider_id"] == p["provider_id"]
        and r["source_record_id"] == p["source_record_id"]
    ]
    if any(r["revision_id"] == p["revision_id"] for r in previous):
        raise DuplicateEvidenceError("Duplicate revision_id for a source record")
    newest = previous[-1]["evidence_id"] if previous else None
    if p["supersedes_evidence_id"] != newest:
        raise RegistryValidationError(
            f"Revision must supersede latest evidence_id ({newest!r}); forks are refused"
        )


class EvidenceLedger:
    """Metadata-only, single-writer JSONL pilot with fail-closed verification."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _verify_and_load(self) -> list[dict]:
        if self.path.is_symlink():
            raise LedgerIntegrityError("Symlink ledger path is not supported")
        if not self.path.exists():
            return []
        if not self.path.is_file():
            raise LedgerIntegrityError("Ledger path is not a regular file")
        if self.path.stat().st_size > _MAX_LEDGER_BYTES:
            raise LedgerIntegrityError("v0.2 pilot ledger exceeds 32 MiB")

        result: list[dict] = []
        seen: list[dict] = []
        prev_hash = GENESIS_HASH
        try:
            with self.path.open("rb") as f:
                for index, raw in enumerate(f):
                    if len(raw) > _MAX_LINE_BYTES:
                        raise LedgerIntegrityError(f"Oversized ledger line {index + 1}")
                    if not raw.endswith(b"\n"):
                        raise LedgerIntegrityError(f"Truncated ledger line {index + 1}")
                    item = json.loads(raw.decode("utf-8"))
                    if not isinstance(item, dict) or set(item) != {
                        "entry_index", "previous_entry_hash", "recorded_at_utc",
                        "payload", "entry_hash",
                    }:
                        raise LedgerIntegrityError(f"Bad ledger structure at line {index + 1}")
                    if type(item["entry_index"]) is not int or item["entry_index"] != index:
                        raise LedgerIntegrityError(f"Bad index at line {index + 1}")
                    if item["previous_entry_hash"] != prev_hash:
                        raise LedgerIntegrityError(f"Broken hash linkage at line {index + 1}")
                    timestamp = item["recorded_at_utc"]
                    if _optional_timestamp("recorded_at_utc", timestamp) != timestamp:
                        raise LedgerIntegrityError("Noncanonical entry timestamp")
                    payload = item["payload"]
                    _validate_payload(payload)
                    if payload["observed_at_utc"] != timestamp:
                        raise LedgerIntegrityError("Receipt timestamp disagrees with entry timestamp")
                    _validate_revision(payload, seen)
                    before_hash = dict(item)
                    supplied_hash = before_hash.pop("entry_hash")
                    if not isinstance(supplied_hash, str) or not _SHA_RE.fullmatch(supplied_hash):
                        raise LedgerIntegrityError("Invalid entry hash format")
                    if _digest(before_hash) != supplied_hash:
                        raise LedgerIntegrityError(f"Entry hash mismatch at line {index + 1}")
                    prev_hash = supplied_hash
                    seen.append(payload)
                    result.append(item)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, LedgerIntegrityError):
                raise
            raise LedgerIntegrityError(f"Invalid ledger: {exc}") from exc
        return result

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        # Basic local crash-safe lock; a stale lock requires manual inspection.
        lock = Path(str(self.path) + ".lock")
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise LedgerIntegrityError(
                f"Existing lock at {lock}; inspect before manual cleanup"
            ) from exc
        try:
            os.close(fd)
            yield
        finally:
            lock.unlink(missing_ok=True)

    def append(
        self,
        *,
        evidence_id: str,
        provider_id: str,
        source_record_id: str,
        revision_id: str,
        content: bytes,
        registered_latency_seconds: int,
        rights_class: str,
        source_published_at: str | None = None,
        supersedes_evidence_id: str | None = None,
    ) -> dict:
        """Append a metadata receipt; never persists `content` bytes.

        Only use with material you are authorized to process. For user/vendor
        datasets keep even metadata and hashes OUT of the public repository.
        """
        for key, value in (
            ("evidence_id", evidence_id), ("provider_id", provider_id),
            ("source_record_id", source_record_id), ("revision_id", revision_id),
        ):
            _required_id(key, value)
        if supersedes_evidence_id is not None:
            _required_id("supersedes_evidence_id", supersedes_evidence_id)
        if type(content) is not bytes or len(content) > _MAX_CONTENT_BYTES:
            raise RegistryValidationError("content must be bytes (<=16 MiB)")
        if rights_class not in RIGHTS_CLASSES:
            raise RegistryValidationError("Unknown rights_class")
        if type(registered_latency_seconds) is not int or registered_latency_seconds < 0:
            raise RegistryValidationError("Latency must be a non-negative integer")
        normalized_published = _optional_timestamp("source_published_at", source_published_at)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._exclusive_lock():
            rows = self._verify_and_load()  # No append to an invalid history.
            stamp = _utc_now()
            payload = {
                "schema_version": SCHEMA_VERSION,
                "evidence_id": evidence_id,
                "provider_id": provider_id,
                "source_record_id": source_record_id,
                "revision_id": revision_id,
                "supersedes_evidence_id": supersedes_evidence_id,
                "source_published_at_utc": normalized_published,
                "observed_at_utc": stamp,
                "availability_upper_at_utc": stamp,
                "registered_latency_seconds": registered_latency_seconds,
                "content_sha256": sha256(content).hexdigest(),
                "rights_class": rights_class,
                "time_basis": TIME_BASIS,
                "raw_content_stored": False,
            }
            _validate_payload(payload)
            _validate_revision(payload, [r["payload"] for r in rows])
            item = {
                "entry_index": len(rows),
                "previous_entry_hash": rows[-1]["entry_hash"] if rows else GENESIS_HASH,
                "recorded_at_utc": stamp,
                "payload": payload,
            }
            item["entry_hash"] = _digest(item)
            serialized = _canonical(item) + b"\n"
            if len(serialized) > _MAX_LINE_BYTES:
                raise RegistryValidationError("Ledger entry exceeds line size limit")
            if self.path.exists() and self.path.stat().st_size + len(serialized) > _MAX_LEDGER_BYTES:
                raise RegistryValidationError("v0.2 pilot ledger would exceed 32 MiB")
            fd = os.open(str(self.path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                written = os.write(fd, serialized)
                if written != len(serialized):
                    raise LedgerIntegrityError("Incomplete write; inspect ledger before retry")
                os.fsync(fd)
            finally:
                os.close(fd)
        return item

    def verify(self) -> dict:
        rows = self._verify_and_load()
        return {
            "status": "STRUCTURALLY_VALID_NOT_INDEPENDENTLY_ATTESTED",
            "integrity_valid": True,
            "entry_count": len(rows),
            "head_hash": rows[-1]["entry_hash"] if rows else GENESIS_HASH,
        }

    def audit(self, evidence_id: str, decision_at: str) -> dict:
        """Time gate with verified chain. Never promotes to full PIT-certified."""
        base = {
            "evidence_id": evidence_id,
            "pit_certified": False,
            "time_gate_pass": False,
            "registry_integrity_verified": False,
            "evidence_proof_class": TIME_BASIS,
        }
        try:
            rows = self._verify_and_load()
        except LedgerIntegrityError as exc:
            return {**base, "status": "HOLD_LEDGER_INTEGRITY", "diagnostic": str(exc)}
        base["registry_integrity_verified"] = True
        matches = [r for r in rows if r["payload"]["evidence_id"] == evidence_id]
        if not matches:
            return {**base, "status": "HOLD_EVIDENCE_NOT_FOUND"}
        item = matches[0]
        payload = item["payload"]
        gate = audit_time_gate(
            evidence_id=payload["evidence_id"],
            decision_at=decision_at,
            availability_upper_at=payload["availability_upper_at_utc"],
            registered_latency_seconds=payload["registered_latency_seconds"],
            source_published_at=payload["source_published_at_utc"],
        )
        gate.update(base)
        gate["time_gate_pass"] = (
            gate["status"] == "TIME_GATE_PASS_UNVERIFIED"
        )
        gate["entry_hash"] = item["entry_hash"]
        gate["rights_class"] = payload["rights_class"]
        return gate
