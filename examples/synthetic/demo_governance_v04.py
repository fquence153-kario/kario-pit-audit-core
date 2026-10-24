"""Offline synthetic governance preflight. Never reads vendor data."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kario_pit.governance import GovernancePreflight
from kario_pit.registry import EvidenceLedger


def utc(dt):
    return dt.isoformat().replace("+00:00", "Z")


def main():
    ap = argparse.ArgumentParser(description="KARIO v0.4 synthetic governance demo")
    ap.add_argument("--ledger", required=True, help="Nonexistent output path")
    args = ap.parse_args()
    path = Path(args.ledger)
    if path.exists() or path.is_symlink():
        ap.error("Refusing to overwrite existing ledger")

    ledger = EvidenceLedger(path)
    src = utc(datetime.now(timezone.utc) - timedelta(seconds=2))
    row = ledger.append(
        evidence_id="SYN-GOV-R1", provider_id="MOCK", source_record_id="SYN-GOV",
        revision_id="R1", content=b"SYNTHETIC_NON_VENDOR_FIXTURE",
        registered_latency_seconds=30, source_published_at=src,
        rights_class="SYNTHETIC_PUBLIC",
    )
    receipt_at = datetime.fromisoformat(row["recorded_at_utc"].replace("Z", "+00:00"))
    decision = utc(receipt_at + timedelta(seconds=30))
    gov = GovernancePreflight(path, synthetic_fixture_ids={"SYN-GOV-R1"})
    values = {
        "synthetic_ledger": str(path),
        "local_ledger_verification": ledger.verify(),
        "public_synthetic_demo": gov.assess(
            provider_id="MOCK", source_record_id="SYN-GOV",
            decision_at=decision, requested_use="PUBLIC_SYNTHETIC_DEMO",
        ),
        "cloud_use_denied": gov.assess(
            provider_id="MOCK", source_record_id="SYN-GOV",
            decision_at=decision, requested_use="CLOUD_PROCESSING",
        ),
        "explanation": "Synthetic policy only; NOT trusted time or legal permission",
    }
    print(json.dumps(values, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
