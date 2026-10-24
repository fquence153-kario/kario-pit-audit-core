"""Purely synthetic private-LABELLED local audit demo, not client data."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path

from kario_pit.intake import import_local_file
from kario_pit.private import PrivateLocalAuditor
from kario_pit.registry import EvidenceLedger
from kario_pit.replay import DecisionReplayer
from kario_pit.audit.time_gate import parse_utc

FIELDS = [
    "evidence_id", "provider_id", "source_record_id", "revision_id",
    "supersedes_evidence_id", "source_published_at", "registered_latency_seconds",
    "rights_class", "content_text",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()
    out = args.output_dir
    if out.exists():
        ap.error("output-dir must be a new directory (refuse overwrite)")
    out.mkdir(parents=True)
    ledger = out / "private_ledger.jsonl"
    csv_path = out / "private_labelled_r1.csv"
    jsonl_path = out / "private_labelled_r2.jsonl"
    published = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    base = dict(provider_id="CUSTOMER_OWNED_DEMO", source_record_id="DEMO_ARTICLE",
                source_published_at=published, registered_latency_seconds=0,
                rights_class="OWNED_PRIVATE")
    r1 = {**base, "evidence_id": "SYNTHETIC-PRIVATE-LABEL-1", "revision_id": "R1",
          "supersedes_evidence_id": None,
          "content_text": "FAKE CUSTOMER-OWNED-LABELLED R1. NOT FINANCIAL OR VENDOR DATA."}
    r2 = {**base, "evidence_id": "SYNTHETIC-PRIVATE-LABEL-2", "revision_id": "R2",
          "supersedes_evidence_id": "SYNTHETIC-PRIVATE-LABEL-1",
          "content_text": "FAKE CUSTOMER-OWNED-LABELLED R2. NOT FINANCIAL OR VENDOR DATA."}

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerow(r1)
    jsonl_path.write_text(json.dumps(r2) + "\n", encoding="utf-8")

    first = import_local_file(csv_path, ledger, mode="LOCAL_OWNED_PRIVATE", apply=True,
                              acknowledge_private_rights=True)
    assert first["batch_committed"]
    t1 = EvidenceLedger(ledger)._verify_and_load()[-1]["recorded_at_utc"]
    second = import_local_file(jsonl_path, ledger, mode="LOCAL_OWNED_PRIVATE", apply=True,
                               acknowledge_private_rights=True)
    assert second["batch_committed"]
    t2 = (parse_utc(EvidenceLedger(ledger)._verify_and_load()[-1]["recorded_at_utc"])
          + timedelta(seconds=1)).isoformat()
    pin = sha256(ledger.read_bytes()).hexdigest()
    auditor = PrivateLocalAuditor(ledger)

    common = dict(provider_id="CUSTOMER_OWNED_DEMO", source_record_id="DEMO_ARTICLE",
                  expected_ledger_sha256=pin, acknowledge_local_rights=True,
                  detail_level="LOCAL_FULL", acknowledge_private_detail=True)
    first_report = auditor.audit_document(decision_at=t1, **common)
    second_report = auditor.audit_document(decision_at=t2, **common)
    denied = auditor.audit_document(decision_at=t2, **{**common,
        "requested_use": "CLOUD_PRIVATE_AUDIT", "detail_level": "REDACTED"})
    unpinned = auditor.audit_document(decision_at=t2, **{**common,
        "expected_ledger_sha256": "0"*64, "detail_level": "REDACTED"})
    public = DecisionReplayer(ledger).replay_document(
        provider_id="CUSTOMER_OWNED_DEMO", source_record_id="DEMO_ARTICLE", decision_at=t2)

    report = {
        "schema_version": "KARIO_PRIVATE_AUDIT_DEMO_V0.7",
        "ledger_integrity_valid": EvidenceLedger(ledger).verify()["integrity_valid"],
        "ledger_entries": EvidenceLedger(ledger).verify()["entry_count"],
        "source_ledger_unchanged": sha256(ledger.read_bytes()).hexdigest() == pin,
        "private_r1_selected_before_r2": first_report.get("selected_revision_id") == "R1",
        "private_r2_selected_after_receipt": second_report.get("selected_revision_id") == "R2",
        "public_replay_still_denied": public["status"] == "HOLD_RIGHTS_POLICY",
        "cloud_use_denied": denied["status"] == "HOLD_INVALID_USE",
        "wrong_pin_denied": unpinned["status"] == "HOLD_LEDGER_PIN_MISMATCH",
        "private_details_in_public_review": False,
        "pit_certified": second_report["pit_certified"],
        "trusted_time_verified": second_report["trusted_time_verified"],
        "rights_legally_cleared": second_report["rights_legally_cleared"],
        "external_export_authorized": second_report["external_export_authorized"],
        "notice": "Synthetic text only. OWNED_PRIVATE is a test label, not legal evidence.",
    }
    assert report["ledger_entries"] == 2
    assert all(report[k] for k in (
        "private_r1_selected_before_r2", "private_r2_selected_after_receipt",
        "public_replay_still_denied", "cloud_use_denied", "wrong_pin_denied",
        "ledger_integrity_valid", "source_ledger_unchanged"))
    assert not any(report[k] for k in ("pit_certified", "trusted_time_verified",
                                       "rights_legally_cleared", "external_export_authorized"))
    (out / "review.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
