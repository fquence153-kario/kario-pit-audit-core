"""Synthetic RFC3161 offline cryptographic proof lab, no vendor inputs."""
import inspect
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from hashlib import sha256

from kario_pit.attestation.rfc3161_offline import (
    RFC3161OfflineLab, _inspect_token_request, entry_commitment,
)
from kario_pit.registry import EvidenceLedger

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples' / 'synthetic'))
from tsa_lab_fixture_v04c import POLICY_OID, make_fixture


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL CLI required for RFC3161 lab')
class RFC3161OfflineV04CTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kario_v04c_tests_')
        cls.dir = Path(cls.temp.name)
        cls.path = cls.dir / 'synthetic.jsonl'
        cls.openssl = shutil.which('openssl')
        cls.ledger = EvidenceLedger(cls.path)
        cls.row = cls.ledger.append(
            evidence_id='SYN-RFC-TEST', provider_id='MOCK',
            source_record_id='ONE', revision_id='R1',
            rights_class='SYNTHETIC_PUBLIC', content=b'KARIO ONLY SYNTHETIC 001',
            registered_latency_seconds=0,
            source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat())
        cls.f = make_fixture(cls.dir / 'keys', openssl_executable=cls.openssl,
                             commitment=entry_commitment(cls.row))
        cls.token = cls.f['token'].read_bytes()
        cls.request = cls.f['request'].read_bytes()
        cls.recorded = datetime.fromisoformat(cls.row['recorded_at_utc'].replace('Z', '+00:00'))
        cls.decision = (cls.recorded + timedelta(minutes=2)).isoformat()
        cls.verifier = cls.make_verifier()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def make_verifier(cls, **kw):
        opts = dict(
            synthetic_fixture_ids={'SYN-RFC-TEST'},
            root_ca_pem_path=cls.f['ca'], extra_cert_pem_path=cls.f['tsa'],
            allowed_policy_oids={POLICY_OID}, openssl_executable=cls.openssl,
        )
        opts.update(kw)
        return RFC3161OfflineLab(cls.path, **opts)

    def query(self, verifier=None, **overrides):
        opts = dict(evidence_id='SYN-RFC-TEST', decision_at=self.decision,
                    token_der=self.token, request_der=self.request)
        opts.update(overrides)
        return (verifier or self.verifier).assess(**opts)

    def test_real_openssl_token_crypto_verifies(self):
        r = self.query()
        self.assertEqual(r['status'], 'RFC3161_CRYPTO_VALID_UNATTESTED')
        self.assertTrue(r['token_crypto_verified'])
        self.assertTrue(r['token_time_gate_pass'])

    def test_valid_crypto_does_not_certify_pit(self):
        r = self.query()
        for k in ('trusted_time_verified', 'external_attestation_verified',
                  'pit_certified', 'rights_legally_cleared'):
            self.assertFalse(r[k])

    def test_ledger_commitment_binds_entry_and_revision(self):
        first = entry_commitment(self.row)
        modified = {**self.row, 'payload': {**self.row['payload'], 'revision_id': 'R2'}}
        self.assertNotEqual(first, entry_commitment(modified))
        self.assertNotEqual(sha256(first).hexdigest(), sha256(entry_commitment(modified)).hexdigest())

    def test_mangled_signature_denied(self):
        mutated = self.token[:-4] + bytes([self.token[-4] ^ 0x01]) + self.token[-3:]
        r = self.query(token_der=mutated)
        self.assertFalse(r['token_crypto_verified'])
        self.assertTrue(r['status'].startswith('HOLD_'))

    def test_wrong_query_denied(self):
        from asn1crypto import tsp
        r = tsp.TimeStampReq.load(self.request)
        r['nonce'] = r['nonce'].native + 1
        out = self.query(request_der=r.dump())
        self.assertEqual(out['status'], 'HOLD_TOKEN_SEMANTICS')

    def test_wrong_policy_denied(self):
        bad = self.make_verifier(allowed_policy_oids={'1.3.6.1.4.1.55555.999'})
        self.assertEqual(self.query(bad)['status'], 'HOLD_TOKEN_SEMANTICS')

    def test_empty_policy_denied(self):
        self.assertEqual(self.query(self.make_verifier(allowed_policy_oids=set()))['status'],
                         'HOLD_POLICY_NOT_CONFIGURED')

    def test_missing_anchor_denied(self):
        bad = self.make_verifier(root_ca_pem_path=self.dir / 'missing.pem')
        self.assertEqual(self.query(bad)['status'], 'HOLD_TRUST_ANCHOR_MISSING')

    def test_wrong_trust_anchor_denied(self):
        bad = self.make_verifier(root_ca_pem_path=self.f['tsa'])
        self.assertEqual(self.query(bad)['status'], 'HOLD_SIGNATURE_OR_CHAIN')

    def test_unknown_evidence_denied(self):
        self.assertEqual(self.query(evidence_id='FAKE')['status'], 'HOLD_FIXTURE_NOT_ALLOWED')

    def test_cloud_denied_before_crypto(self):
        self.assertEqual(self.query(requested_use='CLOUD_PROCESSING')['status'], 'HOLD_INVALID_USE')

    def test_future_token_does_not_pass_decision_boundary(self):
        r = self.query(decision_at=(self.recorded + timedelta(microseconds=100)).isoformat())
        self.assertTrue(r['status'] in ('HOLD_TOKEN_AFTER_DECISION', 'HOLD_LOCAL_TIME_GATE'))
        self.assertFalse(r['token_time_gate_pass'])

    def test_decision_before_receipt_denied(self):
        r = self.query(decision_at=(self.recorded - timedelta(seconds=1)).isoformat())
        self.assertEqual(r['status'], 'HOLD_LOCAL_TIME_GATE')

    def test_cli_missing_fails_closed(self):
        bad = self.make_verifier(openssl_executable='KARIO_OPENS_SL_DOES_NOT_EXIST')
        self.assertEqual(self.query(bad)['status'], 'HOLD_OPENSSL_UNAVAILABLE')

    def test_token_invalid_encoding_fails_closed(self):
        self.assertEqual(self.query(token_der=b'not-a-token')['status'], 'HOLD_TOKEN_SEMANTICS')

    def test_ledger_read_only(self):
        old = self.path.read_bytes()
        self.query()
        self.assertEqual(self.path.read_bytes(), old)

    def test_corrupt_ledger_fails_closed(self):
        bad_path = self.dir / 'corrupt.jsonl'
        bad_path.write_bytes(self.path.read_bytes().replace(b'SYN-RFC-TEST', b'SYN-RFC-FAIL'))
        bad = RFC3161OfflineLab(bad_path, synthetic_fixture_ids={'SYN-RFC-TEST'},
                               root_ca_pem_path=self.f['ca'], extra_cert_pem_path=self.f['tsa'],
                               allowed_policy_oids={POLICY_OID}, openssl_executable=self.openssl)
        self.assertEqual(self.query(bad)['status'], 'HOLD_LEDGER_INTEGRITY')

    def test_missing_request_fails_closed(self):
        self.assertEqual(self.query(request_der=b'')['status'], 'HOLD_INVALID_INPUT')

    def test_unknown_fixture_denied(self):
        bad = self.make_verifier(synthetic_fixture_ids=set())
        self.assertEqual(self.query(bad)['status'], 'HOLD_FIXTURE_NOT_ALLOWED')

    def test_hash_matches_rfc3161_request(self):
        inspect_tst = _inspect_token_request(self.token, self.request,
                                             sha256(entry_commitment(self.row)).digest(),
                                             frozenset({POLICY_OID}))
        self.assertEqual(inspect_tst['policy_oid'], POLICY_OID)
        self.assertLessEqual(inspect_tst['gen_time_utc'], inspect_tst['gen_time_upper_utc'])


class RFC3161NoVendorTests(unittest.TestCase):
    def test_no_vendor_sdk_or_network_use(self):
        from kario_pit.attestation import rfc3161_offline
        src = inspect.getsource(rfc3161_offline)
        for banned in ('import lseg', 'import refinitiv', 'requests.', 'urllib.request', 'httpx.'):
            self.assertNotIn(banned, src)

    def test_invalid_commitment_refused(self):
        with self.assertRaises(ValueError):
            entry_commitment({'entry_hash': '0' * 64, 'payload': {'content_sha256': 'x'}})


if __name__ == '__main__':
    unittest.main()
