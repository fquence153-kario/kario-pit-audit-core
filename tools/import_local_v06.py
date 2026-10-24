"""Offline v0.6 CSV/JSONL pilot CLI. No external data license implied."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kario_pit.intake import IntakeError, import_local_file


def main():
    ap = argparse.ArgumentParser(description="KARIO v0.6 local-only metadata intake")
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--mode", choices=["LOCAL_SYNTHETIC", "LOCAL_OWNED_PRIVATE"],
                    default="LOCAL_SYNTHETIC")
    ap.add_argument("--acknowledge-private-rights", action="store_true")
    ap.add_argument("--apply", action="store_true", help="Write; omitted = read-only dry run")
    args = ap.parse_args()
    try:
        result = import_local_file(
            args.input, args.ledger, mode=args.mode, apply=args.apply,
            acknowledge_private_rights=args.acknowledge_private_rights,
        )
    except (IntakeError, OSError, ValueError) as exc:
        print(f"KARIO v0.6 INTAKE HOLD: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
