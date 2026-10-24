from datetime import datetime, timedelta, timezone
import re

POLICY_VERSION = "KARIO_TIME_GATE_V0.1"
_EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def parse_utc(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    dt = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Timezone is required")

    return dt.astimezone(timezone.utc)


def audit_time_gate(
    evidence_id,
    decision_at,
    availability_upper_at,
    registered_latency_seconds,
    source_published_at=None,
):
    result = {
        "policy_version": POLICY_VERSION,
        "evidence_id": (evidence_id if isinstance(evidence_id, str)
                        and _EVIDENCE_ID_RE.fullmatch(evidence_id) else None),
        "time_gate_pass": False,
        "pit_certified": False,
        "status": "HOLD_INVALID_INPUT",
        "effective_available_at_utc": None,
    }

    try:
        if result["evidence_id"] is None:
            raise ValueError("Evidence ID required")

        decision = parse_utc(decision_at)

        if type(registered_latency_seconds) is not int:
            raise ValueError("Latency must be an integer")

        if registered_latency_seconds < 0:
            raise ValueError("Negative latency")

        if availability_upper_at is None:
            result["status"] = "HOLD_MISSING_AVAILABILITY"
            return result

        upper = parse_utc(availability_upper_at)

        if source_published_at is not None:
            published = parse_utc(source_published_at)
            if upper < published:
                result["status"] = "HOLD_CHRONOLOGY_CONFLICT"
                return result

        effective = upper + timedelta(
            seconds=registered_latency_seconds
        )

        result["effective_available_at_utc"] = (
            effective.isoformat().replace("+00:00", "Z")
        )

        if effective <= decision:
            result["time_gate_pass"] = True
            result["status"] = "TIME_GATE_PASS_UNVERIFIED"
        else:
            result["status"] = "HOLD_AFTER_DECISION"

    except (ValueError, TypeError, OverflowError):
        result["status"] = "HOLD_INVALID_INPUT"
        result["diagnostic"] = "INVALID_TIME_GATE_INPUT"

    return result
