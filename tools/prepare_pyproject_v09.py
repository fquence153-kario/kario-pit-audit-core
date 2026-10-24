"""Precisely scoped opt-in v0.9 pyproject metadata upgrade; never publish.

Dry-run by default. With --apply, require an exact known v0.8A pre-release
metadata block, back up the old file outside the source tree, then atomically
upgrade the version and entry point. No other code files are touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

SCHEMA = "KARIO_V0_9_PACKAGING_METADATA"
V08 = 'version = "0.8.0.dev0"'
V09 = 'version = "0.9.0.dev0"'
MARK = '[tool.setuptools.packages.find]'
SCRIPTS = '[project.scripts]\nkario-pit = "kario_pit.cli_v09:main"\n\n'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch(root: Path, archive: Path, apply: bool = False) -> dict:
    root = Path(root).resolve(strict=True)
    archive = Path(archive).resolve(strict=False)
    target = root / 'pyproject.toml'
    if not root.is_dir() or not target.is_file() or target.is_symlink():
        raise ValueError('unsafe project metadata path')
    if archive == root or root in archive.parents or archive.is_symlink():
        raise ValueError('archive must be outside repository')
    raw = target.read_bytes()
    if len(raw) > 65536:
        raise ValueError('unexpected metadata size')
    try:
        doc = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('metadata must be UTF-8') from exc
    required = ('name = "kario-pit-audit-core"', 'license = "Apache-2.0"',
                '"asn1crypto==1.5.1"', '"cryptography==46.0.4"', MARK)
    if any(doc.count(key) != 1 for key in required):
        raise ValueError('metadata differs from expected v0.8A structure')
    if V09 in doc and doc.count(SCRIPTS.strip()) == 1 and V08 not in doc:
        return {"schema_version": SCHEMA, "status": "ALREADY_APPLIED", "changed": False,
                "public_release_authorized": False}
    if doc.count(V08) != 1 or '[project.scripts]' in doc:
        raise ValueError('unknown pre-existing version or console scripts')
    updated = doc.replace(V08, V09, 1).replace(MARK, SCRIPTS + MARK, 1)
    if updated == doc:
        raise ValueError('could not safely patch metadata')
    if not apply:
        return {"schema_version": SCHEMA, "status": "PLAN_ONLY", "changed": False,
                "public_release_authorized": False}
    archive.mkdir(parents=True, exist_ok=True)
    backup = archive / ('pyproject_v08a_' + sha(raw)[:20] + '.toml.bak')
    if backup.exists() and backup.read_bytes() != raw:
        raise ValueError('backup conflict')
    if not backup.exists():
        backup.write_bytes(raw)
    if backup.read_bytes() != raw:
        raise ValueError('backup failed')
    # Refuse if someone modified metadata during review.
    if target.read_bytes() != raw:
        raise ValueError('metadata changed during operation')
    fd, temporary = tempfile.mkstemp(prefix='.kario_v09_', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(updated.encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"schema_version": SCHEMA, "status": "APPLIED_LOCAL_ONLY", "changed": True,
            "public_release_authorized": False}


def main() -> int:
    parser = argparse.ArgumentParser(description='KARIO v0.9 opt-in packaging metadata update')
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        result = patch(args.root, args.archive, args.apply)
    except (ValueError, OSError) as exc:
        print(json.dumps({"schema_version": SCHEMA, "status": "REFUSED", "reason": type(exc).__name__,
                          "public_release_authorized": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
