"""Offline synthetic R1/R2 replay; never reads existing vendor data."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time

from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer


def utc(dt):
    return dt.isoformat().replace("+00:00", "Z")


def as_datetime(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def main():
    parser = argparse.ArgumentParser(
        description="KARIO v0.3 synthetic decision replay (NO vendor content)"
    )
    parser.add_argument("--ledger", required=True, help="New file path; refuses overwrite")
    args = parser.parse_args()
    path = Path(args.ledger)
    if path.exists() or path.is_symlink():
        parser.error("Output path already exists; choose another synthetic demo filename")

    ledger = EvidenceLedger(path)
    source1 = utc(datetime.now(timezone.utc) - timedelta(seconds=2))
    r1 = ledger.append(
        evidence_id="SYN-REPLAY-R1", provider_id="MOCK",
        source_record_id="SYN-REPLAY-DOC", revision_id="R1",
        source_published_at=source1,
        content=b"SYNTHETIC_PUBLIC_MOCK_REVISION_R1",
        registered_latency_seconds=30,
        rights_class="SYNTHETIC_PUBLIC",
    )
    # Separate local receipts; never backdate the actual demo clock.
    time.sleep(0.02)
    source2 = utc(datetime.now(timezone.utc) - timedelta(seconds=1))
    r2 = ledger.append(
        evidence_id="SYN-REPLAY-R2", provider_id="MOCK",
        source_record_id="SYN-REPLAY-DOC", revision_id="R2",
        supersedes_evidence_id="SYN-REPLAY-R1",
        source_published_at=source2,
        content=b"SYNTHETIC_PUBLIC_MOCK_REVISION_R2",
        registered_latency_seconds=30,
        rights_class="SYNTHETIC_PUBLIC",
    )

    rep = DecisionReplayer(path)
    obs1 = as_datetime(r1["recorded_at_utc"])
    obs2 = as_datetime(r2["recorded_at_utc"])

    def at(dt):
        return rep.replay_document(
            provider_id="MOCK", source_record_id="SYN-REPLAY-DOC",
            decision_at=utc(dt),
        )

    print(json.dumps({
        "synthetic_ledger": str(path),
        "registry_verification": ledger.verify(),
        "before_R1_effective": at(obs1 + timedelta(seconds=29)),
        "after_R1_effective_before_R2": at(obs1 + timedelta(seconds=30)),
        "after_R2_effective": at(obs2 + timedelta(seconds=30)),
        "warning": "Local untrusted receipts, NOT certified historical PIT evidence",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
