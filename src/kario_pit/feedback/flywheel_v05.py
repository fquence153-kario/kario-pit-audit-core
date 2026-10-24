"""KARIO v0.5 synthetic-only audit feedback flywheel (research laboratory).

The feedback journal is independent from the source evidence ledger. It stores
only enumerated issue codes, synthetic evidence references, review decisions,
and deterministic baseline regression checks. It NEVER alters the source audit,
certifies a PIT claim, promotes a rule or authorizes supplier data usage.

Hash chains are LOCAL integrity checks, not independently anchored evidence.
Recorded timestamps are LOCAL clock observations, not trusted historical time.
Not for use with LSEG/Reuters or other restricted/licensed/private data.
No network, vendor SDK, LLM, source content bytes, or automatic training.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import os
import re
from contextlib import contextmanager

from kario_pit.audit.time_gate import audit_time_gate, parse_utc
from kario_pit.registry.ledger import EvidenceLedger, LedgerIntegrityError

SCHEMA_VERSION = "KARIO_FEEDBACK_FLYWHEEL_V0.5_LAB"
GENESIS_HASH = "0" * 64
ISSUE_CODES = frozenset({
    "SOURCE_PROVENANCE_GAP", "TIME_SEMANTICS_CONFLICT", "REVISION_LINEAGE_GAP",
    "LATENCY_POLICY_GAP", "RIGHTS_CLASSIFICATION_GAP", "ATTESTATION_GAP",
})
ADJUDICATIONS = frozenset({"CONFIRMED", "REJECTED", "NEEDS_MORE_EVIDENCE"})
CHANGE_CODES = frozenset({
    "PROVENANCE_RULE_CANDIDATE", "TIME_POLICY_CANDIDATE", "REVISION_RULE_CANDIDATE",
    "LATENCY_RULE_CANDIDATE", "RIGHTS_RULE_CANDIDATE", "ATTESTATION_RULE_CANDIDATE",
})
_ALLOWED_BY_ISSUE = {
    "SOURCE_PROVENANCE_GAP": "PROVENANCE_RULE_CANDIDATE",
    "TIME_SEMANTICS_CONFLICT": "TIME_POLICY_CANDIDATE",
    "REVISION_LINEAGE_GAP": "REVISION_RULE_CANDIDATE",
    "LATENCY_POLICY_GAP": "LATENCY_RULE_CANDIDATE",
    "RIGHTS_CLASSIFICATION_GAP": "RIGHTS_RULE_CANDIDATE",
    "ATTESTATION_GAP": "ATTESTATION_RULE_CANDIDATE",
}
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_LINE_BYTES = 8192
_EVENT_FIELDS = frozenset({"seq", "previous_hash", "recorded_at_utc", "event_type", "payload", "event_hash"})
_PAYLOAD_FIELDS = {
    "CASE_OPENED": frozenset({"case_id", "evidence_id", "entry_hash", "decision_at_utc",
                                  "baseline_status", "issue_code", "reporter_id", "rights_class"}),
    "CASE_ADJUDICATED": frozenset({"case_id", "reviewer_id", "verdict"}),
    "RULE_PROPOSED": frozenset({"case_id", "proposal_id", "candidate_policy_version",
                                 "change_code", "proposer_id"}),
    "BASELINE_REGRESSION": frozenset({"proposal_id", "cases_run", "cases_passed",
                                      "regression_sha256", "scope"}),
    "CANDIDATE_FROZEN": frozenset({"proposal_id", "approver_id", "state"}),
}


class FeedbackValidationError(ValueError):
    """Action violates the synthetic feedback contract or workflow."""


class FeedbackIntegrityError(RuntimeError):
    """Feedback/source journal integrity invalid; fail closed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _require_id(name: str, value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise FeedbackValidationError(f"Invalid {name}")
    return value


def _require_sha(name: str, value: object) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise FeedbackValidationError(f"Invalid {name}")
    return value


def _normalize_utc(value: str) -> str:
    try:
        return parse_utc(value).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError) as exc:
        raise FeedbackValidationError("Timezone-aware timestamp required") from exc


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe_status(status: object) -> str:
    if not isinstance(status, str) or not _ID.fullmatch(status):
        raise FeedbackValidationError("Unsafe baseline audit status")
    if status != "TIME_GATE_PASS_UNVERIFIED" and not status.startswith("HOLD_"):
        raise FeedbackValidationError("Unsupported baseline audit status")
    return status


def _new_state() -> dict:
    return {"cases": {}, "proposals": {}}


def _apply_event(state: dict, kind: str, p: object) -> None:
    """Validate exact schema and replay a journal mutation deterministically."""
    if kind not in _PAYLOAD_FIELDS or not isinstance(p, dict) or frozenset(p) != _PAYLOAD_FIELDS[kind]:
        raise FeedbackValidationError("Unsupported event payload")
    cases, proposals = state["cases"], state["proposals"]
    if kind == "CASE_OPENED":
        case_id = _require_id("case_id", p["case_id"])
        _require_id("evidence_id", p["evidence_id"])
        _require_sha("entry_hash", p["entry_hash"])
        if p["decision_at_utc"] != _normalize_utc(p["decision_at_utc"]):
            raise FeedbackValidationError("Decision timestamp not canonical UTC")
        _safe_status(p["baseline_status"])
        if p["issue_code"] not in ISSUE_CODES or p["rights_class"] != "SYNTHETIC_PUBLIC":
            raise FeedbackValidationError("Only listed synthetic issue codes allowed")
        _require_id("reporter_id", p["reporter_id"])
        if case_id in cases:
            raise FeedbackValidationError("Duplicate case ID")
        cases[case_id] = {**p, "verdict": None, "reviewer_id": None, "proposal_id": None}
    elif kind == "CASE_ADJUDICATED":
        case_id = _require_id("case_id", p["case_id"])
        reviewer = _require_id("reviewer_id", p["reviewer_id"])
        case = cases.get(case_id)
        if case is None or case["verdict"] is not None:
            raise FeedbackValidationError("Case absent or already adjudicated")
        if reviewer == case["reporter_id"]:
            raise FeedbackValidationError("Independent human reviewer required")
        if p["verdict"] not in ADJUDICATIONS:
            raise FeedbackValidationError("Unsupported adjudication")
        case["verdict"] = p["verdict"]
        case["reviewer_id"] = reviewer
    elif kind == "RULE_PROPOSED":
        case_id = _require_id("case_id", p["case_id"])
        proposal = _require_id("proposal_id", p["proposal_id"])
        policy = _require_id("candidate_policy_version", p["candidate_policy_version"])
        proposer = _require_id("proposer_id", p["proposer_id"])
        case = cases.get(case_id)
        if (case is None or case["verdict"] != "CONFIRMED" or
                case["proposal_id"] is not None or proposal in proposals):
            raise FeedbackValidationError("Only one rule candidate from a confirmed case")
        if p["change_code"] != _ALLOWED_BY_ISSUE[case["issue_code"]]:
            raise FeedbackValidationError("Candidate change is inconsistent with issue")
        if policy == "KARIO_TIME_GATE_V0.1":
            raise FeedbackValidationError("Candidate must use a distinct version")
        if any(row["candidate_policy_version"] == policy for row in proposals.values()):
            raise FeedbackValidationError("Candidate policy version already registered")
        case["proposal_id"] = proposal
        proposals[proposal] = {**p, "baseline_regression": None, "frozen_by": None,
                               "state": "PROPOSED_NOT_IMPLEMENTED"}
    elif kind == "BASELINE_REGRESSION":
        proposal = _require_id("proposal_id", p["proposal_id"])
        row = proposals.get(proposal)
        if row is None or row["baseline_regression"] is not None:
            raise FeedbackValidationError("Missing proposal or duplicate regression")
        if (type(p["cases_run"]) is not int or type(p["cases_passed"]) is not int or
                p["cases_run"] != 6 or p["cases_passed"] != 6 or
                p["scope"] != "BUILTIN_BASELINE_ONLY_CANDIDATE_NOT_EVALUATED"):
            raise FeedbackValidationError("Invalid baseline regression result")
        _require_sha("regression_sha256", p["regression_sha256"])
        if p["regression_sha256"] != _baseline_result(proposal, row["candidate_policy_version"])["sha256"]:
            raise FeedbackValidationError("Baseline regression hash did not match actual scenarios")
        row["baseline_regression"] = p["regression_sha256"]
        row["state"] = "BASELINE_REGRESSION_RECORDED_CANDIDATE_UNTESTED"
    elif kind == "CANDIDATE_FROZEN":
        proposal = _require_id("proposal_id", p["proposal_id"])
        approver = _require_id("approver_id", p["approver_id"])
        row = proposals.get(proposal)
        if row is None or row["baseline_regression"] is None or row["frozen_by"] is not None:
            raise FeedbackValidationError("Candidate not ready for freeze")
        case = cases[row["case_id"]]
        if approver in {case["reporter_id"], case["reviewer_id"], row["proposer_id"]}:
            raise FeedbackValidationError("Independent freeze reviewer required")
        if p["state"] != "FROZEN_FOR_REVIEW_NOT_PROMOTED":
            raise FeedbackValidationError("No production promotion in v0.5")
        row["frozen_by"] = approver
        row["state"] = p["state"]


def _baseline_result(proposal_id: str, policy_version: str) -> dict:
    """Run SIX actual deterministic v0.1 baseline scenarios, NOT a new rule spec."""
    base = dict(evidence_id="SYN-FEEDBACK-REGRESSION", decision_at="2026-01-02T10:00:35Z",
                availability_upper_at="2026-01-02T10:00:05Z", registered_latency_seconds=30,
                source_published_at="2026-01-02T10:00:00Z")
    cases = (
        ("boundary_pass", {}, "TIME_GATE_PASS_UNVERIFIED"),
        ("before_boundary", {"decision_at": "2026-01-02T10:00:34Z"}, "HOLD_AFTER_DECISION"),
        ("missing_upper", {"availability_upper_at": None}, "HOLD_MISSING_AVAILABILITY"),
        ("chronology", {"source_published_at": "2026-01-02T10:00:06Z"}, "HOLD_CHRONOLOGY_CONFLICT"),
        ("naive_time", {"decision_at": "2026-01-02T10:00:35"}, "HOLD_INVALID_INPUT"),
        ("negative_latency", {"registered_latency_seconds": -1}, "HOLD_INVALID_INPUT"),
    )
    observations = []
    for label, changes, expected in cases:
        output = audit_time_gate(**{**base, **changes})
        passed = output.get("status") == expected and output.get("pit_certified") is False
        observations.append({"scenario": label, "status": output.get("status"), "pass": passed})
    result = {
        "proposal_id": proposal_id, "candidate_policy_version": policy_version,
        "scope": "BUILTIN_BASELINE_ONLY_CANDIDATE_NOT_EVALUATED", "scenarios": observations,
    }
    result["sha256"] = _hash(result)
    result["passed"] = all(row["pass"] for row in observations)
    result["count"] = len(observations)
    return result


class FeedbackFlywheel:
    """Independent synthetic-only local feedback journal anchored to v0.2 ledger.

    There is no rule activation, no PIT promotion, and no data/model export.
    """

    def __init__(self, source_ledger_path: str | Path, feedback_path: str | Path):
        self.source_path = Path(source_ledger_path)
        self.feedback_path = Path(feedback_path)
        if self.source_path.resolve() == self.feedback_path.resolve():
            raise FeedbackValidationError("Feedback journal cannot replace source ledger")
        self.source = EvidenceLedger(self.source_path)

    def _check_source(self, evidence_id: str, decision_at_utc: str, *, expected_hash: str | None = None,
                      expected_status: str | None = None) -> dict:
        _require_id("evidence_id", evidence_id)
        at = _normalize_utc(decision_at_utc)
        try:
            source_rows = self.source._verify_and_load()
        except (LedgerIntegrityError, OSError) as exc:
            raise FeedbackIntegrityError("Source evidence ledger is invalid or unavailable") from exc
        matches = [r for r in source_rows if r["payload"]["evidence_id"] == evidence_id]
        if len(matches) != 1:
            raise FeedbackValidationError("Evidence not present in verified source ledger")
        entry = matches[0]
        if entry["payload"]["rights_class"] != "SYNTHETIC_PUBLIC":
            raise FeedbackValidationError("Private and vendor data excluded from public feedback lab")
        audit = self.source.audit(evidence_id, at)
        if not audit.get("registry_integrity_verified"):
            raise FeedbackIntegrityError("Source audit did not verify")
        if audit.get("pit_certified") is not False:
            raise FeedbackValidationError("v0.5 requires unverified baseline")
        status = _safe_status(audit.get("status"))
        if expected_hash is not None and entry["entry_hash"] != expected_hash:
            raise FeedbackIntegrityError("Evidence binding changed")
        if expected_status is not None and status != expected_status:
            raise FeedbackIntegrityError("Baseline audit changed")
        return {"entry_hash": entry["entry_hash"], "baseline_status": status, "decision_at_utc": at}

    def _load(self) -> tuple[list[dict], dict]:
        path = self.feedback_path
        if path.is_symlink():
            raise FeedbackIntegrityError("Symlink feedback journal not permitted")
        if not path.exists():
            return [], _new_state()
        if not path.is_file() or path.stat().st_size > _MAX_JOURNAL_BYTES:
            raise FeedbackIntegrityError("Feedback journal missing/oversized/not regular")
        rows = []
        state = _new_state()
        previous_hash = GENESIS_HASH
        last_stamp = None
        try:
            with path.open("rb") as handle:
                for index, raw in enumerate(handle):
                    if len(raw) > _MAX_LINE_BYTES or not raw.endswith(b"\n"):
                        raise FeedbackIntegrityError("Oversized or truncated feedback entry")
                    item = json.loads(raw.decode("utf-8"))
                    if not isinstance(item, dict) or frozenset(item) != _EVENT_FIELDS:
                        raise FeedbackIntegrityError("Invalid event structure")
                    if type(item["seq"]) is not int or item["seq"] != index or item["previous_hash"] != previous_hash:
                        raise FeedbackIntegrityError("Broken feedback event sequence")
                    stamp = item["recorded_at_utc"]
                    if stamp != _normalize_utc(stamp):
                        raise FeedbackIntegrityError("Invalid feedback event clock")
                    if last_stamp is not None and parse_utc(stamp) < parse_utc(last_stamp):
                        raise FeedbackIntegrityError("Feedback clock regression")
                    last_stamp = stamp
                    copy = dict(item)
                    supplied_hash = copy.pop("event_hash")
                    _require_sha("event_hash", supplied_hash)
                    if _hash(copy) != supplied_hash:
                        raise FeedbackIntegrityError("Feedback hash mismatch")
                    _apply_event(state, item["event_type"], item["payload"])
                    previous_hash = supplied_hash
                    rows.append(item)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, OverflowError) as exc:
            if isinstance(exc, FeedbackIntegrityError):
                raise
            raise FeedbackIntegrityError("Corrupted feedback journal") from exc
        # Verify all synthetic source references on every read/write; fail closed.
        for case in state["cases"].values():
            self._check_source(case["evidence_id"], case["decision_at_utc"],
                               expected_hash=case["entry_hash"], expected_status=case["baseline_status"])
        return rows, state

    @contextmanager
    def _lock(self):
        lock = Path(str(self.feedback_path) + ".lock")
        try:
            handle = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise FeedbackIntegrityError("Feedback writer lock present") from exc
        try:
            os.close(handle)
            yield
        finally:
            lock.unlink(missing_ok=True)

    def _write(self, kind: str, payload: dict) -> dict:
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock():
            rows, state = self._load()
            _apply_event(state, kind, payload)
            stamp = _now_utc()
            if rows and parse_utc(stamp) < parse_utc(rows[-1]["recorded_at_utc"]):
                raise FeedbackIntegrityError("Wall-clock regression during append")
            item = {
                "seq": len(rows), "previous_hash": rows[-1]["event_hash"] if rows else GENESIS_HASH,
                "recorded_at_utc": stamp, "event_type": kind, "payload": payload,
            }
            item["event_hash"] = _hash(item)
            raw = _canonical(item) + b"\n"
            if len(raw) > _MAX_LINE_BYTES:
                raise FeedbackValidationError("Feedback event too large")
            if self.feedback_path.exists() and self.feedback_path.stat().st_size + len(raw) > _MAX_JOURNAL_BYTES:
                raise FeedbackValidationError("Feedback journal exceeds pilot size")
            fd = os.open(str(self.feedback_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                written = os.write(fd, raw)
                if written != len(raw):
                    raise FeedbackIntegrityError("Feedback append partial write")
                os.fsync(fd)
            finally:
                os.close(fd)
            return item

    def open_case(self, *, case_id: str, evidence_id: str, decision_at: str,
                  issue_code: str, reporter_id: str) -> dict:
        # Validate all scalar arguments before opening any source or feedback file.
        _require_id("case_id", case_id)
        _require_id("reporter_id", reporter_id)
        if issue_code not in ISSUE_CODES:
            raise FeedbackValidationError("Unknown issue code")
        source = self._check_source(evidence_id, decision_at)
        payload = {
            "case_id": case_id, "evidence_id": evidence_id, "entry_hash": source["entry_hash"],
            "decision_at_utc": source["decision_at_utc"], "baseline_status": source["baseline_status"],
            "issue_code": issue_code, "reporter_id": reporter_id, "rights_class": "SYNTHETIC_PUBLIC",
        }
        return self._write("CASE_OPENED", payload)

    def adjudicate(self, *, case_id: str, reviewer_id: str, verdict: str) -> dict:
        return self._write("CASE_ADJUDICATED", {
            "case_id": case_id, "reviewer_id": reviewer_id, "verdict": verdict,
        })

    def propose_rule(self, *, case_id: str, proposal_id: str, candidate_policy_version: str,
                     change_code: str, proposer_id: str) -> dict:
        return self._write("RULE_PROPOSED", {
            "case_id": case_id, "proposal_id": proposal_id,
            "candidate_policy_version": candidate_policy_version,
            "change_code": change_code, "proposer_id": proposer_id,
        })

    def run_baseline_regressions(self, *, proposal_id: str) -> dict:
        """Actual baseline tests only; DOES NOT TEST OR ACTIVATE candidate policy."""
        _require_id("proposal_id", proposal_id)
        _, state = self._load()
        proposal = state["proposals"].get(proposal_id)
        if proposal is None:
            raise FeedbackValidationError("Unknown candidate proposal")
        result = _baseline_result(proposal_id, proposal["candidate_policy_version"])
        if not result["passed"] or result["count"] != 6:
            raise FeedbackValidationError("Baseline regression unsuccessful")
        return self._write("BASELINE_REGRESSION", {
            "proposal_id": proposal_id, "cases_run": result["count"], "cases_passed": result["count"],
            "regression_sha256": result["sha256"],
            "scope": "BUILTIN_BASELINE_ONLY_CANDIDATE_NOT_EVALUATED",
        })

    def freeze_candidate(self, *, proposal_id: str, approver_id: str) -> dict:
        return self._write("CANDIDATE_FROZEN", {
            "proposal_id": proposal_id, "approver_id": approver_id,
            "state": "FROZEN_FOR_REVIEW_NOT_PROMOTED",
        })

    def verify(self) -> dict:
        rows, state = self._load()
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "SYNTHETIC_FEEDBACK_STRUCTURALLY_VALID_UNATTESTED",
            "integrity_valid": True, "entry_count": len(rows),
            "head_hash": rows[-1]["event_hash"] if rows else GENESIS_HASH,
            "case_count": len(state["cases"]), "proposal_count": len(state["proposals"]),
            "source_ledger_read_only": True, "rights_legally_cleared": False,
            "trusted_time_verified": False, "pit_certified": False,
            "rule_promoted": False, "model_training_performed": False,
        }

    def summary(self) -> dict:
        _, state = self._load()
        by_issue = {code: 0 for code in sorted(ISSUE_CODES)}
        by_verdict = {code: 0 for code in sorted(ADJUDICATIONS)}
        by_verdict["OPEN"] = 0
        for case in state["cases"].values():
            by_issue[case["issue_code"]] += 1
            by_verdict[case["verdict"] or "OPEN"] += 1
        frozen = sum(p["frozen_by"] is not None for p in state["proposals"].values())
        return {
            "status": "SYNTHETIC_FEEDBACK_SUMMARY_NOT_CERTIFICATION",
            "issue_counts": by_issue, "adjudication_counts": by_verdict,
            "case_count": len(state["cases"]), "proposal_count": len(state["proposals"]),
            "candidate_frozen_count": frozen, "production_rules_activated": 0,
            "training_examples_exported": 0, "pit_certified": False,
            "rights_legally_cleared": False,
        }
