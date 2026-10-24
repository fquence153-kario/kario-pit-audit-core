"""Create and inspect a wheel from an allowlisted source snapshot outside repo.

No network, no git push, no publishing, and no data copied. Build requires
preinstalled setuptools+wheel; does not install dependencies or fetch anything.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def _module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise ValueError('Cannot load local preflight')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build(root: Path, out: Path) -> dict:
    root = Path(root).resolve(strict=True)
    out = Path(out).resolve(strict=False)
    if not root.is_dir() or out == root or root in out.parents or out in root.parents:
        raise ValueError('Source/output paths must be separate')
    scan = _module(root / 'tools' / 'release_preflight_v08.py', 'kario_v09_release_scan')
    review = scan.review_tree(root)
    if review['blocking_findings'] or review['public_release_authorized'] is not False:
        raise ValueError('v0.8 release preflight has blockers or unknown status')
    meta = (root / 'pyproject.toml').read_text(encoding='utf-8')
    if 'version = "0.9.0.dev2"' not in meta or 'kario-pit = "kario_pit.cli_v09:main"' not in meta:
        raise ValueError('v0.9 packaging metadata not configured')
    allowed = {'README.md', 'DATA_RIGHTS.md', 'LICENSE', 'pyproject.toml'}
    allowed |= {c['path'] for c in review['candidate_manifest'] if c['path'].startswith('src/kario_pit/') and c['path'].endswith('.py')}
    if 'src/kario_pit/cli_v09.py' not in allowed or 'src/kario_pit/__main__.py' not in allowed:
        raise ValueError('missing command-line package files')
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='KARIO_v09_build_', dir=out) as scratch:
        stage = Path(scratch) / 'isolated_source'
        stage.mkdir()
        for rel in sorted(allowed):
            source = root / rel
            if source.is_symlink() or not source.is_file():
                raise ValueError('unsafe candidate source')
            target = stage / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        wheel_dir = Path(scratch) / 'wheels'
        wheel_dir.mkdir()
        env = os.environ.copy()
        env['PIP_NO_INDEX'] = '1'
        env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'wheel', '--no-index', '--no-deps',
             '--no-build-isolation', '--wheel-dir', str(wheel_dir), str(stage)],
            cwd=scratch, env=env, capture_output=True, timeout=120, check=False,
        )
        if result.returncode != 0:
            raise ValueError('offline local wheel build failed; check wheel and setuptools in project venv')
        wheels = list(wheel_dir.glob('*.whl'))
        if len(wheels) != 1:
            raise ValueError('unexpected wheel count')
        checker = _module(root / 'tools' / 'check_wheel_v09.py', 'kario_v09_wheel_checker')
        validated = checker.inspect_wheel(wheels[0])
        if validated['status'] != 'CONTENT_ONLY_PASS_MANUAL_REVIEW_REQUIRED':
            raise ValueError('wheel contents failed policy gate')
        dest = out / wheels[0].name
        if dest.exists():
            raise ValueError('refusing to overwrite existing wheel')
        shutil.copyfile(wheels[0], dest)
    return {'schema_version': 'KARIO_OFFLINE_BUILD_V0_9',
            'status': 'LOCAL_WHEEL_CREATED_MANUAL_REVIEW_ONLY',
            'wheel_filename': dest.name, 'public_release_authorized': False,
            'repository_published': False, 'vendor_data_copied': False,
            'pit_certified': False}


def main():
    parser = argparse.ArgumentParser(description='Local offline wheel candidate build; NEVER publish')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.root, args.output_dir)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'schema_version': 'KARIO_OFFLINE_BUILD_V0_9', 'status': 'REFUSED',
                          'reason': type(exc).__name__, 'public_release_authorized': False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
