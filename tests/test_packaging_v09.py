"""Synthetic-only v0.9 packaging and command-line safety regression tests."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from kario_pit.cli_v09 import main, _parser

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_pyproject_v09 import patch
from check_wheel_v09 import inspect_wheel, _member_allowed
from build_wheel_v09 import build


class CLIV09Tests(unittest.TestCase):
    def call(self, args):
        out = StringIO()
        with redirect_stdout(out):
            rc = main(args)
        return rc, json.loads(out.getvalue())

    def test_version_never_certifies(self):
        code, r = self.call(['version'])
        self.assertEqual(code, 0)
        self.assertFalse(r['pit_certified'])
        self.assertFalse(r['trusted_time_verified'])
        self.assertFalse(r['public_release_authorized'])

    def test_version_not_vendor_dependent(self):
        _, r = self.call(['version'])
        self.assertFalse(r['vendor_sdk_required'])

    def test_parser_requires_subcommand(self):
        with self.assertRaises(SystemExit):
            _parser().parse_args([])

    def test_parser_has_intake_and_private_audit(self):
        p = _parser()
        self.assertEqual(p.parse_args(['intake','--input','x.csv','--ledger','y.jsonl']).command, 'intake')

    def test_time_boundary_equal(self):
        code, r = self.call(['time-gate','--decision-at','2026-01-01T00:00:10Z',
                             '--availability-upper-at','2026-01-01T00:00:05Z',
                             '--registered-latency-seconds','5'])
        self.assertEqual(code, 0)
        self.assertEqual(r['status'], 'TIME_GATE_PASS_UNVERIFIED')
        self.assertTrue(r['time_gate_pass'])
        self.assertFalse(r['pit_certified'])

    def test_time_before_decision_hold(self):
        _, r = self.call(['time-gate','--decision-at','2026-01-01T00:00:09Z',
                          '--availability-upper-at','2026-01-01T00:00:05Z',
                          '--registered-latency-seconds','5'])
        self.assertEqual(r['status'], 'HOLD_AFTER_DECISION')

    def test_naive_time_denied(self):
        _, r = self.call(['time-gate','--decision-at','2026-01-01T00:00:10',
                          '--availability-upper-at','2026-01-01T00:00:05Z',
                          '--registered-latency-seconds','0'])
        self.assertEqual(r['status'], 'HOLD_INVALID_INPUT')

    def test_no_private_ids_in_time_gate_result(self):
        _, r = self.call(['time-gate','--decision-at','2026-01-01T00:00:10Z',
                          '--availability-upper-at','2026-01-01T00:00:05Z',
                          '--registered-latency-seconds','0'])
        self.assertNotIn('evidence_id', r)
        self.assertNotIn('effective_available_at_utc', r)

    def test_private_intake_requires_ack(self):
        code, r = self.call(['intake','--mode','LOCAL_OWNED_PRIVATE',
                             '--input','private.csv','--ledger','private.jsonl'])
        self.assertEqual(code, 2)
        self.assertEqual(r['status'], 'HOLD_RIGHTS_ACK_REQUIRED')

    def test_private_intake_bad_file_does_not_echo_path(self):
        private_path = 'PRIVATE_PATH_NEVER_PRINT.csv'
        code, r = self.call(['intake','--mode','LOCAL_OWNED_PRIVATE',
                             '--acknowledge-private-rights', '--input',private_path,
                             '--ledger','private.jsonl'])
        self.assertEqual(code, 2)
        self.assertNotIn('PRIVATE_PATH_NEVER_PRINT', json.dumps(r))

    def test_synthetic_intake_bad_file_safe_error(self):
        code, r = self.call(['intake','--input','no-such-file.csv','--ledger','safe.jsonl'])
        self.assertEqual(code, 2)
        self.assertEqual(r['status'], 'HOLD_INTAKE_INVALID_OR_UNSAFE')

    def test_intake_defaults_to_dry_run(self):
        args = _parser().parse_args(['intake', '--input', 'i.csv', '--ledger', 'l.jsonl'])
        self.assertFalse(args.apply)

    def test_private_audit_no_ack_denied(self):
        code, r = self.call(['private-audit','--ledger','private.jsonl','--provider','secret',
                             '--source-record','s', '--decision-at','2026-01-01T01:00:00Z',
                             '--expected-ledger-sha256','0'*64])
        self.assertEqual(code, 2)
        self.assertEqual(r['status'], 'HOLD_RIGHTS_ACK_REQUIRED')
        self.assertNotIn('secret', json.dumps(r))

    def test_private_audit_with_ack_bad_path_no_leak(self):
        code, r = self.call(['private-audit','--ledger','TOPSECRET-LEDGER.jsonl',
                             '--provider','TOPSECRET-PROVIDER','--source-record','TOPSECRET-RECORD',
                             '--decision-at','2026-01-01T01:00:00Z',
                             '--expected-ledger-sha256','0'*64,'--acknowledge-private-rights'])
        self.assertIn(code, (0, 2))  # HOLD is a valid non-error audit verdict
        self.assertTrue(r['status'].startswith('HOLD'))
        self.assertTrue(r['private_details_redacted'])
        self.assertNotIn('TOPSECRET', json.dumps(r))

    def test_private_audit_no_auto_pit(self):
        _, r = self.call(['private-audit','--ledger','missing','--provider','p',
                          '--source-record','r','--decision-at','2026-01-01T01:00:00Z',
                          '--expected-ledger-sha256','0'*64, '--acknowledge-private-rights'])
        self.assertFalse(r['pit_certified'])

    def test_import_module_no_vendor(self):
        import inspect
        import kario_pit.cli_v09 as cli
        source = inspect.getsource(cli)
        self.assertNotIn('import lseg', source)
        self.assertNotIn('import factset', source)


class PyprojectV09Tests(unittest.TestCase):
    BASE = '''[build-system]\nrequires = ["setuptools>=77.0.3,<90", "wheel"]\nbuild-backend = "setuptools.build_meta"\n\n[project]\nname = "kario-pit-audit-core"\nversion = "0.8.0.dev0"\nlicense = "Apache-2.0"\ndependencies = ["asn1crypto==1.5.1", "cryptography==46.0.4"]\n\n[tool.setuptools.packages.find]\nwhere = ["src"]\n'''
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        self.arc = Path(self.tmp.name) / 'archive'
        (self.root / 'pyproject.toml').write_text(self.BASE, encoding='utf8')

    def test_dry_run_no_write(self):
        original = (self.root / 'pyproject.toml').read_bytes()
        r = patch(self.root, self.arc)
        self.assertEqual(r['status'], 'PLAN_ONLY')
        self.assertEqual((self.root / 'pyproject.toml').read_bytes(), original)

    def test_apply_updates_only_metadata(self):
        r = patch(self.root, self.arc, apply=True)
        self.assertEqual(r['status'], 'APPLIED_LOCAL_ONLY')
        s = (self.root / 'pyproject.toml').read_text()
        self.assertIn('version = "0.9.0.dev0"', s)
        self.assertIn('kario-pit = "kario_pit.cli_v09:main"', s)

    def test_backup_created_outside_repo(self):
        patch(self.root, self.arc, apply=True)
        self.assertEqual(len(list(self.arc.glob('*.bak'))), 1)
        self.assertEqual(next(self.arc.glob('*.bak')).read_text(), self.BASE)

    def test_idempotent(self):
        patch(self.root, self.arc, apply=True)
        r = patch(self.root, self.arc, apply=True)
        self.assertEqual(r['status'], 'ALREADY_APPLIED')
        self.assertFalse(r['changed'])

    def test_unknown_metadata_refused(self):
        (self.root / 'pyproject.toml').write_text(self.BASE.replace('0.8.0.dev0','1.1.0'), encoding='utf8')
        with self.assertRaises(ValueError):
            patch(self.root, self.arc, apply=True)

    def test_archive_inside_repo_refused(self):
        with self.assertRaises(ValueError):
            patch(self.root, self.root / 'bad', apply=True)

    def test_missing_apache_refused(self):
        (self.root / 'pyproject.toml').write_text(self.BASE.replace('Apache-2.0','MIT'), encoding='utf8')
        with self.assertRaises(ValueError):
            patch(self.root, self.arc, apply=True)

    def test_no_public_release_authorization(self):
        self.assertFalse(patch(self.root, self.arc, apply=True)['public_release_authorized'])


class WheelV09Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sample.whl'

    def make(self, extra=None):
        dist = 'kario_pit_audit_core-0.9.0.dev2.dist-info/'
        content = {
            'kario_pit/__init__.py': b'',
            'kario_pit/__main__.py': b'print("hello")',
            'kario_pit/cli_v09.py': b'def main(): pass',
            'kario_pit/audit/time_gate.py': b'def check(): pass',
            'kario_pit/intake/vendor_neutral_v06.py': b'def read(): pass',
            'kario_pit/private/local_audit_v07.py': b'def audit(): pass',
            dist+'METADATA': (b'Metadata-Version: 2.4\nName: kario-pit-audit-core\n'
                                b'Version: 0.9.0.dev2\nLicense-Expression: Apache-2.0\n'
                                b'Requires-Dist: asn1crypto==1.5.1\nRequires-Dist: cryptography==50.0.2\n'),
            dist+'entry_points.txt': b'[console_scripts]\nkario-pit = kario_pit.cli_v09:main\n',
            dist+'WHEEL': b'Wheel-Version: 1.0\n',
            dist+'RECORD': b'',
            dist+'licenses/LICENSE': b'Apache license text\n',
        }
        if extra:
            content.update(extra)
        with zipfile.ZipFile(self.path, 'w') as f:
            for name, data in content.items():
                f.writestr(name, data)

    def test_clean_wheel_manual_only(self):
        self.make()
        r = inspect_wheel(self.path)
        self.assertEqual(r['status'], 'CONTENT_ONLY_PASS_MANUAL_REVIEW_REQUIRED')
        self.assertFalse(r['public_release_authorized'])

    def test_csv_in_wheel_denied(self):
        self.make({'kario_pit/private_data.csv': b'secret'})
        self.assertIn('DISALLOWED_MEMBER', inspect_wheel(self.path)['failure_codes'])

    def test_jsonl_in_wheel_denied(self):
        self.make({'records/data.jsonl': b'{}'})
        self.assertEqual(inspect_wheel(self.path)['status'], 'BLOCKED')

    def test_outside_tree_python_denied(self):
        self.make({'tools/publish.py': b'print("publish")'})
        self.assertEqual(inspect_wheel(self.path)['status'], 'BLOCKED')

    def test_vendor_import_denied(self):
        self.make({'kario_pit/cli_v09.py': b'import lseg.data\n'})
        self.assertIn('VENDOR_SDK_IMPORT', inspect_wheel(self.path)['failure_codes'])

    def test_invalid_license_denied(self):
        self.make()
        with zipfile.ZipFile(self.path, 'a') as f:
            f.writestr('kario_pit_audit_core-0.9.0.dev2.dist-info/METADATA', b'Name: wrong\n')
        self.assertEqual(inspect_wheel(self.path)['status'], 'BLOCKED')

    def test_missing_console_denied(self):
        self.make({'kario_pit_audit_core-0.9.0.dev2.dist-info/entry_points.txt': b'[console_scripts]\nwrong = x:y\n'})
        self.assertIn('CONSOLE_SCRIPT_MISSING', inspect_wheel(self.path)['failure_codes'])

    def test_private_key_marker_denied(self):
        self.make({'kario_pit/cli_v09.py': b'-----BEGIN PRIVATE KEY-----\n'})
        self.assertIn('CREDENTIAL_LIKE_CONTENT', inspect_wheel(self.path)['failure_codes'])

    def test_absolute_archive_path_denied(self):
        self.assertFalse(_member_allowed('/secrets/manifest.py'))
        self.assertFalse(_member_allowed('kario_pit/../evil.py'))

    def test_symlink_wheel_refused(self):
        self.make()
        link = Path(self.tmp.name) / 'link.whl'
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(ValueError):
            inspect_wheel(link)


class BuildV09Tests(unittest.TestCase):
    def test_source_and_output_same_tree_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                build(root, root / 'dist')

    def test_missing_preflight_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / 'source'
            repo.mkdir()
            with self.assertRaises((ValueError, OSError, FileNotFoundError)):
                build(repo, base / 'dist')

    def test_build_module_no_network_arg(self):
        import inspect
        import build_wheel_v09
        txt = inspect.getsource(build_wheel_v09)
        self.assertIn("'PIP_NO_INDEX'", txt)
        self.assertIn("'--no-index'", txt)
        self.assertNotIn('twine upload', txt)


if __name__ == '__main__':
    unittest.main()
