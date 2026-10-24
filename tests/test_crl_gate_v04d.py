"""Synthetic offline CRL policy regression tests; no network or vendor data."""
import inspect
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab, entry_commitment
from kario_pit.attestation.crl_gate_v04d import RFC3161CRLPolicyLab
from kario_pit.registry import EvidenceLedger

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples' / 'synthetic'))
from tsa_lab_fixture_v04c import POLICY_OID, make_fixture
from tsa_crl_fixture_v04d import make_synthetic_crl


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL CLI required for full synthetic CRL integration')
class CRLPolicyLabV04DTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kario_crl_v04d_')
        cls.root = Path(cls.temp.name)
        cls.ledger_path = cls.root / 'ledger.jsonl'
        cls.ledger = EvidenceLedger(cls.ledger_path)
        cls.row = cls.ledger.append(
            evidence_id='SYN-CRL-001', provider_id='MOCK', source_record_id='ONE',
            revision_id='R1', content=b'KARIO SYNTHETIC CRL INPUT ONLY',
            rights_class='SYNTHETIC_PUBLIC', registered_latency_seconds=0,
            source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=2)).isoformat())
        cls.f = make_fixture(cls.root / 'keys', openssl_executable=shutil.which('openssl'),
                             commitment=entry_commitment(cls.row))
        cls.ca = x509.load_pem_x509_certificate(cls.f['ca'].read_bytes())
        cls.pin = cls.ca.fingerprint(hashes.SHA256()).hex()
        cls.crl = cls.root / 'active.crl'
        cls.crl_key = cls.f['ca'].parent / 'ca.key'
        cls.make_crl(cls.crl)
        cls.lab = RFC3161OfflineLab(cls.ledger_path,
            synthetic_fixture_ids={'SYN-CRL-001'}, root_ca_pem_path=cls.f['ca'],
            extra_cert_pem_path=cls.f['tsa'], allowed_policy_oids={POLICY_OID},
            openssl_executable=shutil.which('openssl'))
        cls.receipt = dict(evidence_id='SYN-CRL-001',
                           decision_at=(datetime.now(timezone.utc)+timedelta(seconds=90)).isoformat(),
                           token_der=cls.f['token'].read_bytes(),
                           request_der=cls.f['request'].read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def make_crl(cls, path, **kwargs):
        return make_synthetic_crl(cls.f['ca'], cls.crl_key, cls.f['tsa'], path, **kwargs)

    def gate(self, **kw):
        return RFC3161CRLPolicyLab(self.lab, crl_pem_path=kw.get('crl', self.crl),
                                  pinned_root_sha256=kw.get('pin', self.pin))

    def query(self, *, gate=None, **kwargs):
        return (gate or self.gate()).assess(**{**self.receipt, **kwargs})

    def issue(self, name, **opts):
        p = self.root / name
        return self.make_crl(p, **opts)

    def test_current_signed_crl_not_listed(self):
        r = self.query()
        self.assertEqual(r['status'], 'CRL_NOT_LISTED_UNATTESTED')
        self.assertTrue(r['crl_evidence_checked'])
        self.assertTrue(r['token_crypto_verified'])
        self.assertEqual(r['tsa_revocation_status'], 'NOT_LISTED_IN_SUPPLIED_CURRENT_CRL')

    def test_signed_crl_does_not_certify_historical_time(self):
        r = self.query()
        for f in ('trusted_time_verified','external_attestation_verified',
                  'pit_certified','rights_legally_cleared'):
            self.assertIs(r[f], False)
        self.assertIn('historical', r['notice'].lower())

    def test_wrong_root_pin_denied(self):
        self.assertEqual(self.query(gate=self.gate(pin='0'*64))['status'], 'HOLD_CRL_ROOT_PIN_MISMATCH')

    def test_missing_root_pin_denied(self):
        self.assertEqual(self.query(gate=self.gate(pin=''))['status'], 'HOLD_CRL_ROOT_PIN_MISSING')

    def test_nonstring_root_pin_denied(self):
        self.assertEqual(self.query(gate=self.gate(pin=None))['status'], 'HOLD_CRL_ROOT_PIN_MISSING')

    def test_missing_crl_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.root/'missing.crl'))['status'],
                         'HOLD_CRL_MISSING_OR_INVALID')

    def test_invalid_crl_denied(self):
        f = self.root/'invalid.crl'; f.write_text('not a signed CRL')
        self.assertEqual(self.query(gate=self.gate(crl=f))['status'], 'HOLD_CRL_MISSING_OR_INVALID')

    def test_stale_crl_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.issue('stale.crl', stale=True)))['status'],
                         'HOLD_CRL_NOT_CURRENT')

    def test_future_crl_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.issue('future.crl', future=True)))['status'],
                         'HOLD_CRL_NOT_CURRENT')

    def test_revoked_signer_denied(self):
        r = self.query(gate=self.gate(crl=self.issue('revoked.crl', revoked=True)))
        self.assertEqual(r['status'], 'HOLD_CRL_SIGNER_REVOKED')
        self.assertFalse(r['crl_evidence_checked'])
        self.assertFalse(r['trusted_time_verified'])

    def test_crl_signature_tamper_denied(self):
        r = self.query(gate=self.gate(crl=self.issue('tampered.crl', tamper=True)))
        self.assertEqual(r['status'], 'HOLD_CRL_SIGNATURE_INVALID')

    def test_crl_missing_number_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.issue('no_num.crl', omit_number=True)))['status'],
                         'HOLD_CRL_PROFILE_INVALID')

    def test_crl_missing_authority_key_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.issue('no_aki.crl', omit_aki=True)))['status'],
                         'HOLD_CRL_PROFILE_INVALID')

    def test_limited_scope_crl_denied(self):
        self.assertEqual(self.query(gate=self.gate(crl=self.issue('limited.crl', limited_scope=True)))['status'],
                         'HOLD_CRL_UNSUPPORTED_SCOPE')

    def test_invalid_signature_token_before_crl(self):
        b = self.receipt['token_der']
        r = self.query(token_der=b[:-3] + b'bad')
        self.assertTrue(r['status'].startswith('HOLD_'))
        self.assertFalse(r['crl_evidence_checked'])

    def test_cloud_use_denied_before_crl(self):
        r = self.query(requested_use='CLOUD_PROCESSING')
        self.assertEqual(r['status'], 'HOLD_INVALID_USE')
        self.assertFalse(r['crl_evidence_checked'])

    def test_training_denied_before_crl(self):
        r = self.query(requested_use='MODEL_TRAINING')
        self.assertEqual(r['status'], 'HOLD_INVALID_USE')

    def test_unknown_evidence_denied_before_crl(self):
        self.assertEqual(self.query(evidence_id='OTHER')['status'], 'HOLD_FIXTURE_NOT_ALLOWED')

    def test_ledger_never_modified(self):
        old = self.ledger_path.read_bytes()
        self.query()
        self.assertEqual(self.ledger_path.read_bytes(), old)

    def test_no_private_keys_or_vendor_data_in_results(self):
        r = repr(self.query())
        self.assertNotIn('-----BEGIN PRIVATE KEY-----', r)
        self.assertNotIn('KARIO SYNTHETIC CRL INPUT ONLY', r)
        self.assertNotIn('ca.key', r)

    def test_issuer_mismatch_denied(self):
        cert = x509.load_pem_x509_certificate(self.f['ca'].read_bytes())
        key = serialization.load_pem_private_key(self.crl_key.read_bytes(), password=None)
        now = datetime.now(timezone.utc)
        crl = (x509.CertificateRevocationListBuilder()
               .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Not KARIO CA')]))
               .last_update(now-timedelta(seconds=30)).next_update(now+timedelta(hours=1))
               .add_extension(x509.CRLNumber(1), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
               .sign(key, hashes.SHA256()))
        f = self.root/'wrong_issuer.crl'; f.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(self.query(gate=self.gate(crl=f))['status'], 'HOLD_CRL_ISSUER_MISMATCH')

    def test_wrong_crl_signing_key_denied(self):
        cert = x509.load_pem_x509_certificate(self.f['ca'].read_bytes())
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        crl = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
               .last_update(now-timedelta(seconds=30)).next_update(now+timedelta(hours=1))
               .add_extension(x509.CRLNumber(1), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(other.public_key()), False)
               .sign(other, hashes.SHA256()))
        f = self.root/'wrong_key.crl'; f.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(self.query(gate=self.gate(crl=f))['status'], 'HOLD_CRL_SIGNATURE_INVALID')

    def test_token_signer_must_match_crl_checked_certificate(self):
        # Another TSA cert can be signed by the SAME CA, while the RFC3161
        # token remains signed by the original TSA. Verifying the CRL against
        # the wrong certificate must never report not revoked.
        ca = x509.load_pem_x509_certificate(self.f['ca'].read_bytes())
        key = serialization.load_pem_private_key(self.crl_key.read_bytes(), password=None)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'Other Synthetic TSA')]))
            .issuer_name(ca.subject).public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(hours=1))
            .not_valid_after(now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True)
            .sign(key, hashes.SHA256()))
        other_path = self.root/'other_tsa.crt'
        other_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        wrong_lab = RFC3161OfflineLab(self.ledger_path,
            synthetic_fixture_ids={'SYN-CRL-001'}, root_ca_pem_path=self.f['ca'],
            extra_cert_pem_path=other_path, allowed_policy_oids={POLICY_OID},
            openssl_executable=shutil.which('openssl'))
        gate = RFC3161CRLPolicyLab(wrong_lab, crl_pem_path=self.crl,
            pinned_root_sha256=self.pin)
        result = self.query(gate=gate)
        self.assertEqual(result['status'], 'HOLD_CRL_SIGNER_IDENTITY_MISMATCH')

    def test_no_network_or_vendor_sdk(self):
        import kario_pit.attestation.crl_gate_v04d as module
        source = inspect.getsource(module)
        for banned in ('import lseg', 'import refinitiv', 'requests.', 'urllib.request', 'httpx.', 'urlopen('):
            self.assertNotIn(banned, source)

    def test_bad_lab_fails_closed(self):
        g = RFC3161CRLPolicyLab(None, crl_pem_path=self.crl,
                                pinned_root_sha256=self.pin)
        self.assertEqual(g.assess(**self.receipt)['status'], 'HOLD_CRL_LAB_NOT_CONFIGURED')


if __name__ == '__main__':
    unittest.main()
