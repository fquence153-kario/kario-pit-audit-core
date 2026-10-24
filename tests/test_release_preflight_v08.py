"""KARIO v0.8 synthetic-only local release-preflight regression tests."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from release_preflight_v08 import (  # noqa: E402
    MANDATORY_GITIGNORE, SCHEMA, _allowed_file, review_tree, write_report, main
)


class ReleasePreflightV08Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kario_v08_case_')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        files = {
            'README.md': 'Synthetic KARIO code demonstration.\n',
            'DATA_RIGHTS.md': 'Only author-generated synthetic test cases.\n',
            '.gitignore': '\n'.join(MANDATORY_GITIGNORE) + '\n',
            'LICENSE': 'SYNTHETIC TEST TEXT. Not a grant of license.\n',
            'pyproject.toml': '[build-system]\nrequires = ["setuptools"]\n',
            'src/kario_pit/audit/sample.py': 'def check():\n    return 1\n',
            'tests/test_example.py': 'import unittest\n',
            'tools/safe.py': 'print("synthetic")\n',
            'examples/synthetic/demo.py': 'print("synthetic")\n',
            'docs/TEST.md': 'No third-party content.\n',
            'requirements-attestation-v04b.txt': 'cryptography==46.0.4\n',
        }
        for relative, content in files.items():
            dst = self.root / relative
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(content, encoding='utf-8')

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding='utf-8')
        return path

    def codes(self, report):
        return {f['code'] for f in report['findings']}

    def test_minimal_clean_scaffold_only_manual_review(self):
        result = review_tree(self.root)
        self.assertEqual(result['status'], 'MANUAL_REVIEW_ONLY')
        self.assertEqual(result['blocking_findings'], 0)
        self.assertFalse(result['public_release_authorized'])

    def test_no_automatic_publication_or_pit_certification(self):
        r = review_tree(self.root)
        self.assertFalse(r['repository_published'])
        self.assertFalse(r['pit_certified'])
        self.assertFalse(r['trusted_time_verified'])
        self.assertFalse(r['data_license_independently_verified'])

    def test_schema_version(self):
        self.assertEqual(review_tree(self.root)['schema_version'], SCHEMA)

    def test_candidates_sorted(self):
        names = [x['path'] for x in review_tree(self.root)['candidate_manifest']]
        self.assertEqual(names, sorted(names))

    def test_candidates_are_relative_not_absolute(self):
        for c in review_tree(self.root)['candidate_manifest']:
            self.assertFalse(c['path'].startswith('/'))
            self.assertNotIn(str(self.base), c['path'])

    def test_manifest_sha256_matches_source_bytes(self):
        report = review_tree(self.root)
        for row in report['candidate_manifest']:
            expected = hashlib.sha256((self.root / row['path']).read_bytes()).hexdigest()
            self.assertEqual(row['sha256'], expected)

    def test_candidate_counts_actual_files(self):
        self.assertEqual(review_tree(self.root)['candidate_count'], 11)

    def test_missing_license_blocks(self):
        (self.root / 'LICENSE').unlink()
        r = review_tree(self.root)
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertIn('MISSING_REQUIRED_FILE', self.codes(r))

    def test_empty_license_blocks(self):
        self.write('LICENSE', '')
        self.assertIn('EMPTY_LICENSE', self.codes(review_tree(self.root)))

    def test_missing_rights_policy_blocks(self):
        (self.root / 'DATA_RIGHTS.md').unlink()
        self.assertIn('MISSING_REQUIRED_FILE', self.codes(review_tree(self.root)))

    def test_empty_rights_policy_blocks(self):
        self.write('DATA_RIGHTS.md', '   \n')
        self.assertIn('EMPTY_DATA_RIGHTS_POLICY', self.codes(review_tree(self.root)))

    def test_missing_pyproject_blocks(self):
        (self.root / 'pyproject.toml').unlink()
        self.assertIn('MISSING_REQUIRED_FILE', self.codes(review_tree(self.root)))

    def test_incomplete_gitignore_blocks(self):
        self.write('.gitignore', '.venv/\n')
        self.assertIn('GITIGNORE_RULE_MISSING', self.codes(review_tree(self.root)))

    def test_unknown_jsonl_never_candidate(self):
        self.write('synthetic_demo.jsonl', '{}\n')
        r = review_tree(self.root)
        self.assertIn('UNAPPROVED_FILE', self.codes(r))
        self.assertNotIn('synthetic_demo.jsonl', [x['path'] for x in r['candidate_manifest']])

    def test_unknown_csv_never_candidate(self):
        self.write('data.csv', 'x,y\n1,2\n')
        r = review_tree(self.root)
        self.assertIn('UNAPPROVED_FILE', self.codes(r))

    def test_unknown_binary_file_never_candidate(self):
        self.write('dump.parquet', b'PAR1\x00')
        self.assertIn('UNAPPROVED_FILE', self.codes(review_tree(self.root)))

    def test_private_top_level_dir_blocks(self):
        self.write('private/restricted.txt', 'fake\n')
        self.assertIn('PRIVATE_DIRECTORY_PRESENT', self.codes(review_tree(self.root)))

    def test_root_data_dir_blocks(self):
        self.write('data/raw.txt', 'fake\n')
        self.assertIn('PRIVATE_DIRECTORY_PRESENT', self.codes(review_tree(self.root)))

    def test_source_code_private_package_is_legitimate(self):
        self.write('src/kario_pit/private/local.py', 'PASS = False\n')
        self.assertEqual(review_tree(self.root)['blocking_findings'], 0)

    def test_venv_not_scanned(self):
        self.write('.venv/Lib/site-packages/private.key', 'synthetic\n')
        r = review_tree(self.root)
        self.assertEqual(r['blocking_findings'], 0)
        self.assertTrue(r['ignored_local_environment_present'])

    def test_pycache_not_scanned(self):
        self.write('tests/__pycache__/test_p.pyc', b'xyz\x00')
        self.assertEqual(review_tree(self.root)['blocking_findings'], 0)

    def test_root_patch_notes_manual_exclusion(self):
        self.write('PATCH_NOTES_V0_7.md', 'Synthetic notes.\n')
        r = review_tree(self.root)
        self.assertIn('PATCH_NOTES_EXCLUDED', self.codes(r))
        self.assertEqual(r['blocking_findings'], 0)

    def test_vendor_name_in_docs_is_not_sdk_import(self):
        self.write('docs/TEST.md', 'Do not redistribute LSEG or Reuters licensed data.\n')
        self.assertNotIn('VENDOR_SDK_IMPORT', self.codes(review_tree(self.root)))

    def test_vendor_python_import_blocks(self):
        self.write('src/kario_pit/audit/sample.py', 'from ' + 'lseg.data import some_sdk\n')
        self.assertIn('VENDOR_SDK_IMPORT', self.codes(review_tree(self.root)))

    def test_legacy_vendor_import_blocks(self):
        self.write('tools/safe.py', 'import ' + 'refinitiv.data\n')
        self.assertIn('VENDOR_SDK_IMPORT', self.codes(review_tree(self.root)))

    def test_pem_private_key_marker_blocks_without_value_leak(self):
        secret = '-----BEGIN ' + 'PRIVATE KEY-----'
        block = secret + '\n' + 'M' * 64 + '\n' + '-----END PRIVATE KEY-----'
        self.write('src/kario_pit/audit/sample.py', block + '\n')
        r = review_tree(self.root)
        self.assertIn('PEM_PRIVATE_KEY', self.codes(r))
        self.assertNotIn('M' * 64, json.dumps(r))

    def test_pem_marker_in_assertion_is_manual_not_secret_leak(self):
        self.write('tests/test_example.py', "assert '-----BEGIN PRIVATE KEY-----' not in ''\n")
        r = review_tree(self.root)
        self.assertEqual(r['blocking_findings'], 0)
        self.assertIn('PEM_HEADER_LITERAL_MANUAL_REVIEW', self.codes(r))

    def test_aws_key_marker_blocks_without_value_leak(self):
        key = 'AKIA' + 'A' * 16
        self.write('docs/TEST.md', key + '\n')
        r = review_tree(self.root)
        self.assertIn('AWS_ACCESS_KEY', self.codes(r))
        self.assertNotIn(key, json.dumps(r))

    def test_github_token_marker_blocks(self):
        token = 'ghp_' + 'Z' * 35
        self.write('tools/safe.py', 'token="' + token + '"\n')
        self.assertIn('GITHUB_TOKEN', self.codes(review_tree(self.root)))

    def test_openai_style_token_blocks(self):
        token = 'sk-' + 'Z' * 30
        self.write('tools/safe.py', 'key="' + token + '"\n')
        self.assertIn('OPENAI_STYLE_TOKEN', self.codes(review_tree(self.root)))

    def test_assigned_client_secret_blocks(self):
        value = 'XX' * 20
        self.write('tools/safe.py', 'client_secret = "' + value + '"\n')
        self.assertIn('ASSIGNED_SECRET', self.codes(review_tree(self.root)))

    def test_invalid_utf8_blocks(self):
        self.write('docs/TEST.md', b'\xff\xfe')
        self.assertIn('INVALID_UTF8_SOURCE', self.codes(review_tree(self.root)))

    def test_oversized_source_blocks(self):
        self.write('docs/TEST.md', 'a' * (1024 * 1024 + 1))
        self.assertIn('OVERSIZE_SOURCE', self.codes(review_tree(self.root)))

    def test_pinned_dependency_inventory_not_licensed(self):
        r = review_tree(self.root)
        self.assertEqual(r['dependency_inventory'], [
            {'package': 'cryptography', 'version': '46.0.4', 'license_review': 'PENDING_MANUAL'}
        ])
        self.assertFalse(r['dependencies_license_cleared'])

    def test_unpinned_dependency_blocks(self):
        self.write('requirements-attestation-v04b.txt', 'cryptography>=42\n')
        self.assertIn('UNREVIEWED_DEPENDENCY_SPEC', self.codes(review_tree(self.root)))

    def test_unapproved_requirements_main_file_blocks(self):
        self.write('requirements.txt', 'requests==2.31.0\n')
        self.assertIn('UNAPPROVED_FILE', self.codes(review_tree(self.root)))

    def test_manifest_scan_does_not_mutate_repository(self):
        before = hashlib.sha256((self.root / 'README.md').read_bytes()).digest()
        review_tree(self.root)
        after = hashlib.sha256((self.root / 'README.md').read_bytes()).digest()
        self.assertEqual(before, after)

    def test_report_outside_repo_writes_json(self):
        report_path = self.base / 'out' / 'report.json'
        r = review_tree(self.root)
        write_report(r, report_path, self.root)
        loaded = json.loads(report_path.read_text(encoding='utf-8'))
        self.assertEqual(loaded['schema_version'], SCHEMA)
        self.assertFalse(loaded['public_release_authorized'])

    def test_report_inside_repo_denied(self):
        with self.assertRaises(ValueError):
            write_report(review_tree(self.root), self.root / 'preflight.json', self.root)

    def test_report_outside_repo_does_not_copy_bytes(self):
        report_path = self.base / 'output.json'
        marker = 'Test synthetic source: only fixture byte content'
        self.write('docs/TEST.md', marker)
        write_report(review_tree(self.root), report_path, self.root)
        self.assertNotIn(marker, report_path.read_text(encoding='utf-8'))

    def test_cli_writes_report_without_publishing(self):
        report_path = self.base / 'report.json'
        rc = main(['--root', str(self.root), '--report', str(report_path)])
        self.assertEqual(rc, 0)
        self.assertTrue(report_path.is_file())
        self.assertFalse(json.loads(report_path.read_text())['public_release_authorized'])

    def test_cli_require_clean_fails_when_blocked(self):
        (self.root / 'LICENSE').unlink()
        rc = main(['--root', str(self.root), '--report', str(self.base / 'out.json'), '--require-clean'])
        self.assertEqual(rc, 1)

    def test_cli_require_clean_allows_manual_only_not_authorized(self):
        report_file = self.base / 'out.json'
        rc = main(['--root', str(self.root), '--report', str(report_file), '--require-clean'])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(report_file.read_text())['status'], 'MANUAL_REVIEW_ONLY')

    def test_git_not_initialized_is_manual_not_public_ready(self):
        r = review_tree(self.root)
        self.assertIn('GIT_INDEX_NOT_AVAILABLE', self.codes(r))
        self.assertFalse(r['git_history_review_completed'])

    def test_git_index_unapproved_file_blocked(self):
        (self.root / '.git').mkdir()
        process = mock.Mock(returncode=0, stdout=b'data/customer.csv\x00README.md\x00')
        with mock.patch('release_preflight_v08.subprocess.run', return_value=process):
            r = review_tree(self.root)
        self.assertIn('UNAPPROVED_GIT_TRACKED_FILE', self.codes(r))
        self.assertEqual(r['git_tracked_count'], 2)

    def test_git_index_command_failure_blocks(self):
        (self.root / '.git').mkdir()
        with mock.patch('release_preflight_v08.subprocess.run', side_effect=OSError):
            self.assertIn('GIT_INDEX_INSPECTION_FAILED', self.codes(review_tree(self.root)))

    def test_symlink_to_data_directory_refused_mocked(self):
        ext = self.root / 'external'
        ext.mkdir()
        original = Path.is_symlink
        with mock.patch.object(Path, 'is_symlink', lambda p: p.name == 'external' or original(p)):
            r = review_tree(self.root)
        self.assertIn('SYMLINK_DIRECTORY_REFUSED', self.codes(r))

    def test_symlink_to_source_refused_mocked(self):
        original = Path.is_symlink
        with mock.patch.object(Path, 'is_symlink', lambda p: p.name == 'sample.py' or original(p)):
            r = review_tree(self.root)
        self.assertIn('SYMLINK_FILE_REFUSED', self.codes(r))

    def test_nonexistent_root_fails(self):
        with self.assertRaises(FileNotFoundError):
            review_tree(self.base / 'missing')

    def test_allowed_file_matrix(self):
        self.assertTrue(_allowed_file('src/kario_pit/audit/time_gate.py'))
        self.assertTrue(_allowed_file('tests/test_foo.py'))
        self.assertFalse(_allowed_file('tests/data.csv'))
        self.assertFalse(_allowed_file('private/customer.jsonl'))
        self.assertFalse(_allowed_file('evidence_20261009.jsonl'))

    def test_pyproject_missing_never_generate_license(self):
        (self.root / 'LICENSE').unlink()
        review_tree(self.root)
        self.assertFalse((self.root / 'LICENSE').exists())

    def test_unknown_log_blocked_with_metadata_only(self):
        marker = 'never-export-demo-log-content'
        self.write('run.log', marker)
        r = review_tree(self.root)
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertNotIn(marker, json.dumps(r))

    def test_scanner_uses_no_network(self):
        with mock.patch('release_preflight_v08.subprocess.run', side_effect=AssertionError('no subprocess expected')):
            self.assertEqual(review_tree(self.root)['blocking_findings'], 0)


if __name__ == '__main__':
    unittest.main()
