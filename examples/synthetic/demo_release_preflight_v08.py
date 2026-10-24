"""Purely synthetic v0.8 demonstration: CLEAN manual-review vs BLOCKED data risk."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from release_preflight_v08 import MANDATORY_GITIGNORE, review_tree, write_report


def build(root: Path, blocked: bool) -> None:
    parts = {
        'README.md': '# Fabricated KARIO example\n',
        'DATA_RIGHTS.md': 'Only synthetic local test data.\n',
        '.gitignore': '\n'.join(MANDATORY_GITIGNORE) + '\n',
        'LICENSE': 'Synthetic placeholder; NOT an actual open-source grant.\n',
        'pyproject.toml': '[build-system]\nrequires=["setuptools"]\n',
        'src/kario_pit/audit/clock.py': 'def decide():\n    return False\n',
        'docs/demo.md': 'No live or vendor data.\n',
    }
    if blocked:
        parts['data/customer_secret.jsonl'] = '{"synthetic_only": true}\n'
    for rel, data in parts.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(data, encoding='utf-8')


def demo(output_dir: Path) -> dict:
    output_dir = Path(output_dir).expanduser().resolve(strict=False)
    if output_dir.exists():
        raise ValueError('Output directory already exists; refuse to overwrite')
    output_dir.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='kario_v08_local_demo_') as tmp:
        root = Path(tmp)
        clean, unsafe = root / 'clean', root / 'blocked'
        clean.mkdir()
        unsafe.mkdir()
        build(clean, False)
        build(unsafe, True)
        clean_report = review_tree(clean)
        blocked_report = review_tree(unsafe)
        write_report(clean_report, output_dir / 'clean_candidate_report.json', clean)
        write_report(blocked_report, output_dir / 'blocked_candidate_report.json', unsafe)
    summary = {
        'clean_preflight_status': clean_report['status'],
        'clean_preflight_blockers': clean_report['blocking_findings'],
        'blocked_preflight_status': blocked_report['status'],
        'blocked_preflight_blockers': blocked_report['blocking_findings'],
        'prohibited_data_detected': any(f['code'] == 'PRIVATE_DIRECTORY_PRESENT' for f in blocked_report['findings']),
        'public_release_authorized': False,
        'repo_published': False,
        'source_data_transferred': False,
        'actual_dependencies_or_licenses_cleared': False,
        'pit_certified': False,
    }
    (output_dir / 'review.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', required=True, type=Path)
    args = p.parse_args()
    result = demo(args.output_dir)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
