"""KARIO v0.6 — bounded offline CSV/JSONL -> local metadata ledger.

Not a vendor connector, license verification service, publication proof, or PIT
certificate. The caller is responsible for data rights. No network or SDK.

The *input* retains raw text at its original private location. The destination
ledger stores only identifiers, source time, locally observed ingest time and
content SHA-256. Even those metadata/hashes can be restricted: never publish
customer ledgers. In particular, the v0.3 public replayer does NOT authorize
private records (HOLD_RIGHTS_POLICY); no new permission is granted here.

Local batch commit uses a verified same-directory staging ledger and os.replace
under the existing v0.2 single-writer lock. It is a local filesystem pilot,
not a distributed transaction or crash-proof replicated database.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import csv
import io
import json
import os
import re
import shutil
import tempfile

from kario_pit.audit.time_gate import parse_utc
from kario_pit.registry import EvidenceLedger, LedgerIntegrityError

SCHEMA_VERSION = "KARIO_VENDOR_NEUTRAL_INTAKE_V0.6"
MODE_SYNTHETIC = "LOCAL_SYNTHETIC"
MODE_PRIVATE = "LOCAL_OWNED_PRIVATE"
RIGHTS_BY_MODE = {
    MODE_SYNTHETIC: "SYNTHETIC_PUBLIC",
    MODE_PRIVATE: "OWNED_PRIVATE",
}
FIELDS = frozenset({
    "evidence_id", "provider_id", "source_record_id", "revision_id",
    "supersedes_evidence_id", "source_published_at",
    "registered_latency_seconds", "rights_class", "content_text",
})
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
INT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = 256 * 1024
MAX_RECORDS = 100
MAX_LATENCY_SECONDS = 7 * 24 * 3600
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class IntakeError(ValueError):
    """Fail-closed input rights, format, structure or version-lineage error."""


@dataclass(frozen=True)
class _Row:
    evidence_id: str
    provider_id: str
    source_record_id: str
    revision_id: str
    supersedes_evidence_id: str | None
    source_published_at: str
    registered_latency_seconds: int
    rights_class: str
    content_bytes: bytes

    def append_kwargs(self):
        return {
            "evidence_id": self.evidence_id,
            "provider_id": self.provider_id,
            "source_record_id": self.source_record_id,
            "revision_id": self.revision_id,
            "supersedes_evidence_id": self.supersedes_evidence_id,
            "source_published_at": self.source_published_at,
            "registered_latency_seconds": self.registered_latency_seconds,
            "rights_class": self.rights_class,
            "content": self.content_bytes,
        }


def _is_within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _validate_paths(source: Path, target: Path, mode: str) -> None:
    if source.is_symlink() or target.is_symlink():
        raise IntakeError("Symlink source/target refused")
    if not source.is_file():
        raise IntakeError("Input must be an existing regular file")
    if source.resolve() == target.resolve():
        raise IntakeError("Input and ledger must be different files")
    if not target.parent.exists() and target.parent.is_symlink():
        raise IntakeError("Symlink destination directory refused")
    if target.exists() and not target.is_file():
        raise IntakeError("Destination ledger must be a regular file")
    # Never write a live intake ledger to the open-source repository, even if
    # all records are labelled synthetic. Synthetic TEST fixture files are okay.
    if _is_within(target.resolve(), PROJECT_ROOT):
        raise IntakeError("Destination ledger cannot be inside source repository")
    if mode == MODE_PRIVATE and _is_within(source.resolve(), PROJECT_ROOT):
        raise IntakeError("Private source cannot be inside source repository")


def _reject_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise IntakeError("Duplicate JSON key")
        obj[key] = value
    return obj


def _reject_json_constant(value):
    raise IntakeError("Non-finite JSON numbers are unsupported")


def _records_from_bytes(raw: bytes, extension: str):
    try:
        data = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IntakeError("Input must be UTF-8") from exc
    if "\x00" in data:
        raise IntakeError("NUL byte in input")

    if extension == ".jsonl":
        rows = []
        for index, line in enumerate(data.splitlines(), start=1):
            if not line.strip():
                raise IntakeError(f"Blank JSONL line {index} refused")
            if len(line.encode("utf-8")) > MAX_ROW_BYTES:
                raise IntakeError(f"Oversized JSONL line {index}")
            try:
                obj = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys,
                                 parse_constant=_reject_json_constant)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise IntakeError(f"Invalid JSONL line {index}") from exc
            rows.append(obj)
            if len(rows) > MAX_RECORDS:
                raise IntakeError("Batch exceeds 100 records")
        return rows
    if extension == ".csv":
        before_limit = csv.field_size_limit()
        try:
            csv.field_size_limit(MAX_ROW_BYTES)
            reader = csv.DictReader(io.StringIO(data, newline=""), strict=True)
            header = reader.fieldnames
            if header is None or len(header) != len(FIELDS) or set(header) != FIELDS:
                raise IntakeError("CSV header must match the exact v0.6 schema")
            rows = []
            try:
                for obj in reader:
                    rows.append(obj)
                    if len(rows) > MAX_RECORDS:
                        raise IntakeError("Batch exceeds 100 records")
            except (csv.Error, OverflowError) as exc:
                raise IntakeError("Malformed or oversized CSV record") from exc
            return rows
        finally:
            csv.field_size_limit(before_limit)
    raise IntakeError("Only .csv and .jsonl input formats are supported")


def _normalize(row: object, index: int, mode: str) -> _Row:
    if not isinstance(row, dict) or set(row) != FIELDS:
        raise IntakeError(f"Record {index}: missing or unexpected fields")
    for name in ("evidence_id", "provider_id", "source_record_id", "revision_id"):
        v = row[name]
        if not isinstance(v, str) or not ID_RE.fullmatch(v):
            raise IntakeError(f"Record {index}: invalid {name}")
    supersedes = row["supersedes_evidence_id"]
    if supersedes == "":  # CSV's representation of an absent predecessor.
        supersedes = None
    if supersedes is not None and (
        not isinstance(supersedes, str) or not ID_RE.fullmatch(supersedes)
    ):
        raise IntakeError(f"Record {index}: invalid supersedes_evidence_id")
    if row["rights_class"] != RIGHTS_BY_MODE[mode]:
        raise IntakeError(f"Record {index}: rights class does not match declared local mode")
    if mode == MODE_SYNTHETIC and (
        row["provider_id"] != "SYNTHETIC" or not row["evidence_id"].startswith("SYN-")
    ):
        raise IntakeError(f"Record {index}: synthetic mode requires synthetic IDs/provider")

    seconds = row["registered_latency_seconds"]
    if isinstance(seconds, str):
        if not INT_RE.fullmatch(seconds):
            raise IntakeError(f"Record {index}: latency must be a non-negative integer")
        seconds = int(seconds)
    if type(seconds) is not int or not (0 <= seconds <= MAX_LATENCY_SECONDS):
        raise IntakeError(f"Record {index}: latency outside allowed 0..604800 range")
    published = row["source_published_at"]
    try:
        normalized_pub = parse_utc(published).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError) as exc:
        raise IntakeError(f"Record {index}: published time must have timezone") from exc
    if parse_utc(normalized_pub) > datetime.now(timezone.utc):
        raise IntakeError(f"Record {index}: future source publication time refused")
    content = row["content_text"]
    if not isinstance(content, str) or not content or "\x00" in content:
        raise IntakeError(f"Record {index}: non-empty text content required")
    content_bytes = content.encode("utf-8")
    if len(content_bytes) > MAX_ROW_BYTES:
        raise IntakeError(f"Record {index}: content too large")
    return _Row(
        row["evidence_id"], row["provider_id"], row["source_record_id"],
        row["revision_id"], supersedes, normalized_pub, seconds,
        row["rights_class"], content_bytes,
    )


def _read_and_prepare(source: Path, mode: str) -> list[_Row]:
    if source.stat().st_size > MAX_FILE_BYTES:
        raise IntakeError("Input file exceeds 2 MiB pilot limit")
    raw = source.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise IntakeError("Input file exceeds 2 MiB pilot limit")
    rows = _records_from_bytes(raw, source.suffix.lower())
    if not rows:
        raise IntakeError("Empty batch refused")
    return [_normalize(record, i, mode) for i, record in enumerate(rows, start=1)]


def _check_lineage(existing: list[dict], prepared: list[_Row]) -> None:
    ids = set()
    current_by_source = {}
    revisions = set()
    rights_by_source = {}
    for item in existing:
        p = item["payload"]
        ids.add(p["evidence_id"])
        key = (p["provider_id"], p["source_record_id"])
        current_by_source[key] = p["evidence_id"]
        revisions.add((*key, p["revision_id"]))
        rights_by_source.setdefault(key, p["rights_class"])
        if rights_by_source[key] != p["rights_class"]:
            raise IntakeError("Existing source has mixed rights classes")
    for idx, row in enumerate(prepared, start=1):
        key = (row.provider_id, row.source_record_id)
        if row.evidence_id in ids:
            raise IntakeError(f"Record {idx}: duplicate evidence ID")
        if (*key, row.revision_id) in revisions:
            raise IntakeError(f"Record {idx}: duplicate source revision")
        if current_by_source.get(key) != row.supersedes_evidence_id:
            raise IntakeError(f"Record {idx}: revision must supersede latest ledger evidence")
        if key in rights_by_source and rights_by_source[key] != row.rights_class:
            raise IntakeError(f"Record {idx}: source rights-class change refused")
        ids.add(row.evidence_id)
        revisions.add((*key, row.revision_id))
        current_by_source[key] = row.evidence_id
        rights_by_source[key] = row.rights_class


def _summary(*, status: str, count: int, before: int, mode: str, committed: bool) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "mode": mode,
        "records_in_batch": count,
        "ledger_entries_before": before,
        "ledger_entries_after": before + count if committed else before,
        "batch_committed": committed,
        "local_ingest_time_basis": "LOCAL_INGEST_RECEIPT_UNATTESTED",
        "raw_content_stored_in_ledger": False,
        "pit_certified": False,
        "trusted_time_verified": False,
        "rights_legally_cleared": False,
        "source_published_time_independently_verified": False,
        "private_data_public_export_authorized": False,
        "notices": [
            "Rights classification is the operator's declaration, not legal clearance.",
            "Metadata and hashes may remain restricted; never publish private ledgers.",
            "v0.3 public replay does not authorize OWNED_PRIVATE data.",
        ],
    }


def import_local_file(
    source_path: str | Path,
    ledger_path: str | Path,
    *,
    mode: str = MODE_SYNTHETIC,
    apply: bool = False,
    acknowledge_private_rights: bool = False,
) -> dict:
    """Validate a local file and optionally atomically append metadata receipts.

    Private mode requires explicit operator acknowledgement and is *local only*.
    This acknowledgement does not establish license rights and never overrides
    the previous synthetic-only governance/replay policies. No data upload.
    """
    if mode not in RIGHTS_BY_MODE:
        raise IntakeError("Only LOCAL_SYNTHETIC or LOCAL_OWNED_PRIVATE mode is supported")
    if mode == MODE_PRIVATE and acknowledge_private_rights is not True:
        raise IntakeError("Private intake requires explicit local-processing rights acknowledgement")
    if type(apply) is not bool:
        raise IntakeError("apply must be a boolean")
    source, target = Path(source_path), Path(ledger_path)
    _validate_paths(source, target, mode)
    prepared = _read_and_prepare(source, mode)
    ledger = EvidenceLedger(target)
    if not apply:
        try:
            rows = ledger._verify_and_load()
        except (OSError, ValueError, LedgerIntegrityError) as exc:
            raise IntakeError("Destination ledger integrity verification failed") from exc
        _check_lineage(rows, prepared)
        return _summary(status="DRY_RUN_LOCAL_UNATTESTED", count=len(prepared),
                        before=len(rows), mode=mode, committed=False)

    target.parent.mkdir(parents=True, exist_ok=True)
    stage_path = None
    # Exactly the same lock naming/protocol as EvidenceLedger.append(); other
    # writers using that legacy API cannot interleave with this transaction.
    with ledger._exclusive_lock():
        try:
            rows = ledger._verify_and_load()
        except (OSError, ValueError, LedgerIntegrityError) as exc:
            raise IntakeError("Destination ledger integrity verification failed") from exc
        _check_lineage(rows, prepared)
        before = len(rows)
        try:
            fd, name = tempfile.mkstemp(prefix=".kario_v06_stage_", suffix=".jsonl",
                                        dir=str(target.parent))
            stage_path = Path(name)
            with os.fdopen(fd, "wb") as temp:
                if target.exists():
                    with target.open("rb") as prior:
                        shutil.copyfileobj(prior, temp, length=1024 * 1024)
                temp.flush()
                os.fsync(temp.fileno())
            stage = EvidenceLedger(stage_path)
            for row in prepared:
                stage.append(**row.append_kwargs())
            verified = stage.verify()
            if not verified["integrity_valid"] or verified["entry_count"] != before + len(prepared):
                raise IntakeError("Staged ledger failed batch verification")
            os.replace(str(stage_path), str(target))
            stage_path = None
        finally:
            if stage_path is not None:
                stage_path.unlink(missing_ok=True)
    return _summary(status="LOCAL_INGEST_COMMITTED_UNATTESTED", count=len(prepared),
                    before=before, mode=mode, committed=True)
