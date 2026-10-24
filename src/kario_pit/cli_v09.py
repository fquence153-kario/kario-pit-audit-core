"""Local-only KARIO PIT Audit Core v0.9 command-line entry point.

This CLI offers no real-time feed, LSEG integration, legal clearance, or PIT
certification. For private data, it deliberately redacts identifiers and file
paths and refuses operations without explicit local-use acknowledgment.
"""
from __future__ import annotations

import argparse
import json
from typing import Sequence

SCHEMA = "KARIO_CLI_V0_9"
FALLBACK_VERSION = "0.9.0.dev2"


def _emit(result: dict) -> None:
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kario-pit", description="Local-first KARIO PIT Audit research prototype (UNATTESTED)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Show installed version and limited assurance flags")

    time = sub.add_parser("time-gate", help="Run local unverified time boundary check")
    time.add_argument("--decision-at", required=True)
    time.add_argument("--availability-upper-at", required=True)
    time.add_argument("--registered-latency-seconds", required=True, type=int)
    time.add_argument("--source-published-at")

    intake = sub.add_parser("intake", help="Validate bounded CSV/JSONL; default is dry run")
    intake.add_argument("--input", required=True)
    intake.add_argument("--ledger", required=True)
    intake.add_argument("--mode", choices=("LOCAL_SYNTHETIC", "LOCAL_OWNED_PRIVATE"), default="LOCAL_SYNTHETIC")
    intake.add_argument("--acknowledge-private-rights", action="store_true")
    intake.add_argument("--apply", action="store_true", help="Explicitly write local metadata ledger")

    private = sub.add_parser("private-audit", help="Run redacted local OWNED_PRIVATE audit (UNATTESTED)")
    private.add_argument("--ledger", required=True)
    private.add_argument("--provider", required=True)
    private.add_argument("--source-record", required=True)
    private.add_argument("--decision-at", required=True)
    private.add_argument("--expected-ledger-sha256", required=True)
    private.add_argument("--acknowledge-private-rights", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        try:
            from importlib.metadata import version, PackageNotFoundError
            try:
                release = version("kario-pit-audit-core")
            except PackageNotFoundError:
                release = FALLBACK_VERSION
        except ImportError:
            release = FALLBACK_VERSION
        _emit({"schema_version": SCHEMA, "version": release,
               "vendor_sdk_required": False, "public_release_authorized": False,
               "pit_certified": False, "trusted_time_verified": False})
        return 0

    if args.command == "time-gate":
        from kario_pit.audit.time_gate import audit_time_gate
        result = audit_time_gate(
            evidence_id="SYN-CLI-TIME-GATE",
            decision_at=args.decision_at,
            availability_upper_at=args.availability_upper_at,
            registered_latency_seconds=args.registered_latency_seconds,
            source_published_at=args.source_published_at,
        )
        # Treat this as a calculation only, not evidence certification.
        _emit({"schema_version": SCHEMA,
               "status": result["status"], "time_gate_pass": result["time_gate_pass"],
               "pit_certified": False, "trusted_time_verified": False,
               "rights_legally_cleared": False, "public_release_authorized": False})
        return 0

    if args.command == "intake":
        if args.mode == "LOCAL_OWNED_PRIVATE" and not args.acknowledge_private_rights:
            _emit({"schema_version": SCHEMA, "status": "HOLD_RIGHTS_ACK_REQUIRED",
                   "pit_certified": False, "rights_legally_cleared": False})
            return 2
        try:
            from kario_pit.intake.vendor_neutral_v06 import import_local_file
            result = import_local_file(args.input, args.ledger, mode=args.mode,
                                       apply=args.apply, acknowledge_private_rights=args.acknowledge_private_rights)
        except (OSError, ValueError, RuntimeError):
            # Never echo exception contents: some errors could mention private paths.
            _emit({"schema_version": SCHEMA, "status": "HOLD_INTAKE_INVALID_OR_UNSAFE",
                   "pit_certified": False, "rights_legally_cleared": False})
            return 2
        _emit(result)  # v0.6 summary contains no raw content, record IDs or input paths.
        return 0

    if args.command == "private-audit":
        if not args.acknowledge_private_rights:
            _emit({"schema_version": SCHEMA, "status": "HOLD_RIGHTS_ACK_REQUIRED",
                   "private_details_redacted": True, "pit_certified": False})
            return 2
        try:
            from kario_pit.private import PrivateLocalAuditor
            result = PrivateLocalAuditor(args.ledger).audit_document(
                provider_id=args.provider,
                source_record_id=args.source_record,
                decision_at=args.decision_at,
                expected_ledger_sha256=args.expected_ledger_sha256,
                acknowledge_local_rights=args.acknowledge_private_rights,
            )
            if result.get("private_details_redacted") is not True:
                raise ValueError("Unsafe result")
        except (OSError, ValueError, KeyError, RuntimeError, TypeError):
            _emit({"schema_version": SCHEMA, "status": "HOLD_PRIVATE_AUDIT_INVALID_OR_UNSAFE",
                   "private_details_redacted": True, "pit_certified": False})
            return 2
        _emit(result)
        return 0
    raise AssertionError("unreachable")
