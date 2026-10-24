"""Offline, deny-by-default v0.9 wheel *content* inspection.

This does not grant permission to publish, verify legal rights, or inspect every
possible malicious behavior. It only detects disallowed files and basic metadata.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

SCHEMA = "KARIO_WHEEL_CONTENT_V0_9"
VERSION = "0.9.0.dev2"
VENDOR_IMPORT = re.compile(r'^\s*(?:import|from)\s+(?:lseg|refinitiv|eikon|factset|ravenpack)(?:\b|\.)', re.I | re.M)
SECRET_MARKERS = (
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    re.compile(r'\bsk-[A-Za-z0-9_-]{24,}\b'),
)
FORBIDDEN_SUFFIXES = ('.csv', '.jsonl', '.log', '.pem', '.key', '.sqlite', '.parquet', '.pkl', '.db', '.zip', '.whl')
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024


def _member_allowed(name: str) -> bool:
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or any(part in ('..', '.', '') for part in p.parts):
        return False
    if name.endswith(FORBIDDEN_SUFFIXES) or '__pycache__' in p.parts:
        return False
    if name.startswith('kario_pit/'):
        return name.endswith('.py') and len(p.parts) >= 2
    if len(p.parts) >= 2 and p.parts[0].endswith('.dist-info'):
        if len(p.parts) == 2:
            return p.parts[1] in {'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt', 'LICENSE'}
        if len(p.parts) == 3:
            return p.parts[1] == 'licenses' and p.parts[2] == 'LICENSE'
    return False


def inspect_wheel(path: str | Path) -> dict:
    path = Path(path)
    failures: list[str] = []
    if not path.is_file() or path.is_symlink():
        raise ValueError('Wheel missing or unsafe')
    if path.stat().st_size > MAX_TOTAL_BYTES:
        raise ValueError('Wheel exceeds inspection size limit')
    try:
        with zipfile.ZipFile(path, 'r') as z:
            members = [i for i in z.infolist() if not i.is_dir()]
            if len(members) != len({i.filename for i in members}):
                failures.append('DUPLICATE_ARCHIVE_NAMES')
            if sum(i.file_size for i in members) > MAX_TOTAL_BYTES:
                failures.append('UNCOMPRESSED_SIZE_EXCEEDED')
            raw_by_name = {}
            for i in members:
                if i.file_size > MAX_MEMBER_BYTES:
                    failures.append('OVERSIZE_MEMBER')
                    continue
                if not _member_allowed(i.filename):
                    failures.append('DISALLOWED_MEMBER')
                    continue
                raw = z.read(i)
                if i.filename.endswith(('.py', '.txt', '.md', 'METADATA', 'WHEEL', 'RECORD', 'LICENSE')):
                    try:
                        s = raw.decode('utf-8')
                    except UnicodeError:
                        failures.append('NON_UTF8_TEXT_MEMBER')
                        continue
                    if any(pattern.search(s) for pattern in SECRET_MARKERS):
                        failures.append('CREDENTIAL_LIKE_CONTENT')
                    if i.filename.endswith('.py') and VENDOR_IMPORT.search(s):
                        failures.append('VENDOR_SDK_IMPORT')
                raw_by_name[i.filename] = raw
            required_code = {'kario_pit/__init__.py', 'kario_pit/__main__.py', 'kario_pit/cli_v09.py',
                             'kario_pit/audit/time_gate.py', 'kario_pit/intake/vendor_neutral_v06.py',
                             'kario_pit/private/local_audit_v07.py'}
            if not required_code.issubset(raw_by_name.keys()):
                failures.append('MISSING_PACKAGE_MODULE')
            infos = [n for n in raw_by_name if n.endswith('.dist-info/METADATA')]
            entries = [n for n in raw_by_name if n.endswith('.dist-info/entry_points.txt')]
            licenses = [n for n in raw_by_name if n.endswith('.dist-info/licenses/LICENSE') or n.endswith('.dist-info/LICENSE')]
            if len(infos) != 1 or len(entries) != 1 or len(licenses) != 1:
                failures.append('REQUIRED_METADATA_MISSING')
            else:
                meta = raw_by_name[infos[0]].decode('utf-8')
                entry = raw_by_name[entries[0]].decode('utf-8')
                # Wheel METADATA may use LF or CRLF on different platforms.
                # Match an optional carriage return, without weakening exact values.
                if not re.search(r'^Name: kario-pit-audit-core\r?$', meta, re.M | re.I):
                    failures.append('UNEXPECTED_PROJECT_NAME')
                if not re.search(r'^Version: ' + re.escape(VERSION) + r'\r?$', meta, re.M):
                    failures.append('UNEXPECTED_VERSION')
                if not re.search(r'^License-Expression: Apache-2\.0\r?$', meta, re.M):
                    failures.append('UNEXPECTED_LICENSE')
                if 'kario-pit = kario_pit.cli_v09:main' not in entry:
                    failures.append('CONSOLE_SCRIPT_MISSING')
                if 'asn1crypto==1.5.1' not in meta or 'cryptography==50.0.2' not in meta:
                    failures.append('UNEXPECTED_DEPENDENCIES')
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
        raise ValueError('Invalid wheel archive') from exc
    failures = sorted(set(failures))
    return {
        'schema_version': SCHEMA,
        'status': 'BLOCKED' if failures else 'CONTENT_ONLY_PASS_MANUAL_REVIEW_REQUIRED',
        'failure_codes': failures,
        'public_release_authorized': False,
        'legal_rights_verified': False,
        'data_license_verified': False,
        'trusted_time_verified': False,
        'pit_certified': False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description='KARIO v0.9 local wheel content check; NEVER publishes')
    ap.add_argument('--wheel', type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = inspect_wheel(args.wheel)
    except (ValueError, OSError) as exc:
        result = {'schema_version': SCHEMA, 'status': 'BLOCKED', 'failure_codes': [type(exc).__name__],
                  'public_release_authorized': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CONTENT_ONLY_PASS_MANUAL_REVIEW_REQUIRED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
