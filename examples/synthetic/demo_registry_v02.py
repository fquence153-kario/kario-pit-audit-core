"""Create exactly one synthetic ledger on a caller-selected local path."""
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from kario_pit.registry import EvidenceLedger


def main():
    parser = argparse.ArgumentParser(
        description="KARIO v0.2 synthetic-only ledger demo, no LSEG dependency"
    )
    parser.add_argument("--ledger", required=True, help="New output JSONL path (must not exist)")
    args = parser.parse_args()
    path = Path(args.ledger)
    if path.exists():
        parser.error("Ledger already exists; refusing overwrite. Choose a new demo path.")
    ledger = EvidenceLedger(path)
    entry = ledger.append(
        evidence_id="SYNTHETIC-EVIDENCE-0001",
        provider_id="MOCK", source_record_id="SYNTHETIC-DOC-0001",
        revision_id="R1", content=b"SYNTHETIC CONTENT, NO VENDOR DATA",
        registered_latency_seconds=30, rights_class="SYNTHETIC_PUBLIC",
    )
    observed = datetime.fromisoformat(entry["recorded_at_utc"].replace("Z", "+00:00"))
    early = (observed + timedelta(seconds=29)).isoformat()
    boundary = (observed + timedelta(seconds=30)).isoformat()
    print(json.dumps({
        "ledger": str(path),
        "verification": ledger.verify(),
        "before_decision": ledger.audit("SYNTHETIC-EVIDENCE-0001", early),
        "at_boundary": ledger.audit("SYNTHETIC-EVIDENCE-0001", boundary),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
