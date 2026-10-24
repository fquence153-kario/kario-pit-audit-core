"""Offline private-only time gate CLI; outputs only REDACTED results."""
from __future__ import annotations

import argparse
import json
from kario_pit.private import PrivateLocalAuditor


def main():
    parser = argparse.ArgumentParser(description="KARIO v0.7 local private audit (unattested)")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--source-record", required=True)
    parser.add_argument("--decision-at", required=True)
    parser.add_argument("--expected-ledger-sha256", required=True)
    parser.add_argument("--acknowledge-private-rights", action="store_true")
    args = parser.parse_args()
    result = PrivateLocalAuditor(args.ledger).audit_document(
        provider_id=args.provider,
        source_record_id=args.source_record,
        decision_at=args.decision_at,
        expected_ledger_sha256=args.expected_ledger_sha256,
        acknowledge_local_rights=args.acknowledge_private_rights,
    )
    # Console output never includes selected evidence IDs, private revisions,
    # raw text, hashes or dataset paths. HOLD is an expected business verdict.
    assert result["private_details_redacted"] is True
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
