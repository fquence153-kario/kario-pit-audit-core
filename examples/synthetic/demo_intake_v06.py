"""Vendor-free CSV then JSONL ingest, R1/R2 historical replay; synthetic only."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from kario_pit.audit.time_gate import parse_utc
from kario_pit.intake import import_local_file
from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer

FIELDS = [
    "evidence_id", "provider_id", "source_record_id", "revision_id",
    "supersedes_evidence_id", "source_published_at",
    "registered_latency_seconds", "rights_class", "content_text",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--jsonl", required=True, type=Path)
    args = parser.parse_args()
    all_paths = [p.resolve() for p in (args.ledger, args.csv, args.jsonl)]
    if len(set(all_paths)) != 3 or any(p.exists() for p in all_paths):
        parser.error("All three output paths must be unique and must not exist")
    for p in all_paths:
        p.parent.mkdir(parents=True, exist_ok=True)

    published = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    base = dict(provider_id="SYNTHETIC", source_record_id="SYN-ARTICLE-1",
                source_published_at=published, registered_latency_seconds=0,
                rights_class="SYNTHETIC_PUBLIC")
    r1 = {**base, "evidence_id": "SYN-INGEST-1", "revision_id": "R1",
          "supersedes_evidence_id": None,
          "content_text": "SYNTHETIC PUBLIC DEMO R1 (no vendor data)"}
    r2 = {**base, "evidence_id": "SYN-INGEST-2", "revision_id": "R2",
          "supersedes_evidence_id": "SYN-INGEST-1",
          "content_text": "SYNTHETIC PUBLIC DEMO R2 (revised)"}

    with args.csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerow(r1)
    args.jsonl.write_text(json.dumps(r2, sort_keys=True) + "\n", encoding="utf-8")
    first_dry = import_local_file(args.csv, args.ledger)
    first = import_local_file(args.csv, args.ledger, apply=True)
    ledger = EvidenceLedger(args.ledger)
    first_rows = ledger._verify_and_load()
    t1 = first_rows[0]["payload"]["observed_at_utc"]
    second_dry = import_local_file(args.jsonl, args.ledger)
    second = import_local_file(args.jsonl, args.ledger, apply=True)
    verification = ledger.verify()
    replay = DecisionReplayer(args.ledger)
    replay_r1 = replay.replay_document(provider_id="SYNTHETIC",
        source_record_id="SYN-ARTICLE-1", decision_at=t1)
    last = ledger._verify_and_load()[-1]
    decision_r2 = (parse_utc(last["recorded_at_utc"]) + timedelta(seconds=2)).isoformat()
    replay_r2 = replay.replay_document(provider_id="SYNTHETIC",
        source_record_id="SYN-ARTICLE-1", decision_at=decision_r2)
    raw_ledger = args.ledger.read_text(encoding="utf-8")
    report = {
        "schema_version": "KARIO_INTAKE_DEMO_V0.6",
        "csv_dry_run": first_dry,
        "jsonl_dry_run": second_dry,
        "csv_committed": first["batch_committed"],
        "jsonl_committed": second["batch_committed"],
        "ledger_verification": verification,
        "replay_R1_at_first_receipt": replay_r1["selected_revision_id"],
        "replay_R2_after_second_receipt": replay_r2["selected_revision_id"],
        "raw_content_absent_from_ledger": (
            r1["content_text"] not in raw_ledger and
            r2["content_text"] not in raw_ledger
        ),
        "trusted_time_verified": False,
        "pit_certified": False,
        "rights_legally_cleared": False,
        "notice": "Synthetic local data only. Import timestamps are local receipt claims, not historical PIT proof.",
    }
    assert verification["entry_count"] == 2
    assert first_dry["ledger_entries_after"] == 0
    assert second_dry["ledger_entries_after"] == 1
    assert report["replay_R1_at_first_receipt"] == "R1"
    assert report["replay_R2_after_second_receipt"] == "R2"
    assert report["raw_content_absent_from_ledger"]
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
