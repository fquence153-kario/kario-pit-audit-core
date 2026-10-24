"""v0.4E synthetic historical archive consistency checks, no vendor access."""
from __future__ import annotations
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from kario_pit.registry import EvidenceLedger
from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab, entry_commitment
from kario_pit.attestation.historical_crl_archive_v04e import (
    HistoricalCRLArchiveLab, make_local_manifest, manifest_json_bytes,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples' / 'synthetic'))
from tsa_lab_fixture_v04c import POLICY_OID, make_fixture
from tsa_crl_fixture_v04d import make_synthetic_crl


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL CLI required')
class HistoricalCRLArchiveV04ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kario_v04e_')
        cls.root = Path(cls.temp.name)
        cls.ledger_path = cls.root/'ledger.jsonl'
        cls.ledger = EvidenceLedger(cls.ledger_path)
        cls.row = cls.ledger.append(
            evidence_id='SYN-ARCHIVE-001', provider_id='MOCK', source_record_id='ARCHIVE',
            revision_id='R1', content=b'KARIO SYNTHETIC ARCHIVE TEST',
            rights_class='SYNTHETIC_PUBLIC', registered_latency_seconds=0,
            source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat())
        cls.f = make_fixture(cls.root/'keys', openssl_executable=shutil.which('openssl'),
                             commitment=entry_commitment(cls.row))
        cls.ca_key = cls.f['ca'].parent/'ca.key'
        cls.active_crl = make_synthetic_crl(cls.f['ca'], cls.ca_key,
                                             cls.f['tsa'], cls.root/'active.crl')
        cls.revoked_crl = make_synthetic_crl(cls.f['ca'], cls.ca_key,
                                              cls.f['tsa'], cls.root/'revoked.crl', revoked=True)
        cls.stale_crl = make_synthetic_crl(cls.f['ca'], cls.ca_key,
                                            cls.f['tsa'], cls.root/'stale.crl', stale=True)
        cls.ca = x509.load_pem_x509_certificate(cls.f['ca'].read_bytes())
        cls.pin = cls.ca.fingerprint(hashes.SHA256()).hex()
        cls.lab = RFC3161OfflineLab(cls.ledger_path,
                                    synthetic_fixture_ids={'SYN-ARCHIVE-001'},
                                    root_ca_pem_path=cls.f['ca'], extra_cert_pem_path=cls.f['tsa'],
                                    allowed_policy_oids={POLICY_OID},
                                    openssl_executable=shutil.which('openssl'))
        cls.data = dict(evidence_id='SYN-ARCHIVE-001',
                        decision_at=(datetime.now(timezone.utc)+timedelta(seconds=90)).isoformat(),
                        token_der=cls.f['token'].read_bytes(),
                        request_der=cls.f['request'].read_bytes())
        cls.observed = datetime.now(timezone.utc).isoformat()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _prepare(self, name='manifest', *, crl=None, observed=None, **changes):
        crl = crl or self.active_crl
        manifest = make_local_manifest(
            archive_id='SYN-ARCHIVE-001', evidence_id=self.data['evidence_id'],
            ledger_entry_hash=self.row['entry_hash'],
            crl_bytes=crl.read_bytes(), tsa_cert_bytes=self.f['tsa'].read_bytes(),
            ca_cert_bytes=self.f['ca'].read_bytes(),
            token_der=self.data['token_der'], request_der=self.data['request_der'],
            first_observed_at_utc=observed or self.observed)
        manifest.update(changes)
        path = self.root/f'{name}_{id(manifest)}.json'
        raw = manifest_json_bytes(manifest)
        path.write_bytes(raw)
        sha = sha256(raw).hexdigest()
        return manifest, path, sha

    def _query(self, *, name='tmp', crl=None, pin=None, observed=None,
               manifest_changes=None, manifest_path=None, manifest_sha=None,
               **data_changes):
        crl = crl or self.active_crl
        if manifest_path is None:
            _, path, sha = self._prepare(name, crl=crl, observed=observed,
                                         **(manifest_changes or {}))
        else:
            path, sha = manifest_path, manifest_sha
        gate = HistoricalCRLArchiveLab(self.lab,
              crl_pem_path=crl, manifest_path=path,
              expected_manifest_sha256=sha,
              pinned_root_sha256=self.pin if pin is None else pin)
        return gate.assess(**{**self.data, **data_changes})

    def test_consistent_local_snapshot(self):
        r = self._query()
        self.assertEqual(r['status'], 'HISTORICAL_CRL_SNAPSHOT_CONSISTENT_UNATTESTED')
        self.assertTrue(r['local_archive_consistency_pass'])
        self.assertTrue(r['token_crypto_verified'])

    def test_no_pit_or_trusted_time_promotion(self):
        r = self._query()
        for flag in ('historical_status_independently_attested', 'trusted_time_verified',
                     'external_attestation_verified','pit_certified','rights_legally_cleared'):
            self.assertIs(r[flag], False)

    def test_manifest_is_canonical(self):
        m, _, _ = self._prepare('canonical')
        self.assertEqual(json.loads(manifest_json_bytes(m)), m)

    def test_modified_manifest_refused(self):
        _, f, sha = self._prepare('modified')
        f.write_bytes(f.read_bytes() + b' ')
        self.assertEqual(self._query(manifest_path=f, manifest_sha=sha)['status'],
                         'HOLD_ARCHIVE_MANIFEST_CHANGED')

    def test_incorrect_manifest_hash_refused(self):
        _, f, _ = self._prepare('sha')
        self.assertEqual(self._query(manifest_path=f, manifest_sha='0'*64)['status'],
                         'HOLD_ARCHIVE_MANIFEST_CHANGED')

    def test_missing_manifest_denied(self):
        self.assertEqual(self._query(manifest_path=self.root/'none.json',
                                     manifest_sha='a'*64)['status'],
                         'HOLD_ARCHIVE_INPUT_UNAVAILABLE')

    def test_manifest_extra_field_denied(self):
        self.assertEqual(self._query(manifest_changes={'extra':'x'})['status'],
                         'HOLD_ARCHIVE_MANIFEST_INVALID')

    def test_manifest_wrong_schema_denied(self):
        self.assertEqual(self._query(manifest_changes={'manifest_version':'X'})['status'],
                         'HOLD_ARCHIVE_MANIFEST_INVALID')

    def test_manifest_false_time_basis_denied(self):
        self.assertEqual(self._query(manifest_changes={'time_basis':'EXTERNALLY_VERIFIED'})['status'],
                         'HOLD_ARCHIVE_MANIFEST_INVALID')

    def test_wrong_evidence_id_denied(self):
        self.assertEqual(self._query(manifest_changes={'evidence_id':'OTHER'})['status'],
                         'HOLD_ARCHIVE_MANIFEST_INVALID')

    def test_bad_entry_hash_denied(self):
        self.assertEqual(self._query(manifest_changes={'ledger_entry_hash':'f'*64})['status'],
                         'HOLD_ARCHIVE_BINDING_MISMATCH')

    def test_wrong_crl_hash_denied(self):
        self.assertEqual(self._query(manifest_changes={'crl_sha256':'f'*64})['status'],
                         'HOLD_ARCHIVE_BINDING_MISMATCH')

    def test_wrong_token_hash_denied(self):
        self.assertEqual(self._query(manifest_changes={'token_sha256':'f'*64})['status'],
                         'HOLD_ARCHIVE_BINDING_MISMATCH')

    def test_wrong_request_hash_denied(self):
        self.assertEqual(self._query(manifest_changes={'request_sha256':'f'*64})['status'],
                         'HOLD_ARCHIVE_BINDING_MISMATCH')

    def test_wrong_root_pin_denied(self):
        self.assertEqual(self._query(pin='0'*64)['status'], 'HOLD_ARCHIVE_ROOT_PIN_MISMATCH')

    def test_missing_root_pin_denied(self):
        self.assertEqual(self._query(pin='')['status'], 'HOLD_ARCHIVE_PIN_MISSING')

    def test_operator_claim_after_decision_denied(self):
        at=(datetime.now(timezone.utc)+timedelta(hours=2)).isoformat()
        self.assertEqual(self._query(observed=at)['status'],
                         'HOLD_ARCHIVE_OBSERVED_AFTER_DECISION')

    def test_operator_claim_before_issuance_denied(self):
        at=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        self.assertEqual(self._query(observed=at)['status'],
                         'HOLD_ARCHIVE_OBSERVED_BEFORE_ISSUED')

    def test_expired_snapshot_at_decision_denied(self):
        at=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()
        self.assertEqual(self._query(decision_at=at)['status'],
                         'HOLD_ARCHIVE_CRL_NOT_VALID_AT_DECISION')

    def test_stale_crl_denied(self):
        self.assertEqual(self._query(crl=self.stale_crl)['status'],
                         'HOLD_ARCHIVE_CRL_NOT_VALID_AT_DECISION')

    def test_revoked_signer_denied(self):
        self.assertEqual(self._query(crl=self.revoked_crl)['status'],
                         'HOLD_ARCHIVE_SIGNER_LISTED')

    def test_cloud_use_denied_before_archive(self):
        self.assertEqual(self._query(requested_use='CLOUD_PROCESSING')['status'],
                         'HOLD_INVALID_USE')

    def test_training_denied_before_archive(self):
        self.assertEqual(self._query(requested_use='MODEL_TRAINING')['status'],
                         'HOLD_INVALID_USE')

    def test_unknown_evidence_denied_before_archive(self):
        self.assertEqual(self._query(evidence_id='OTHER')['status'],
                         'HOLD_FIXTURE_NOT_ALLOWED')

    def test_ledger_readonly(self):
        old = self.ledger_path.read_bytes()
        self._query()
        self.assertEqual(old, self.ledger_path.read_bytes())

    def test_without_vendor_or_network(self):
        import inspect
        from kario_pit.attestation import historical_crl_archive_v04e
        src = inspect.getsource(historical_crl_archive_v04e).lower()
        self.assertNotIn('import lseg', src)
        self.assertNotIn('import refinitiv', src)
        self.assertNotIn('requests.get', src)
        self.assertNotIn('httpx', src)

    def test_manifest_not_private_key_export(self):
        m, _, _ = self._prepare('safety')
        output = json.dumps(m)
        self.assertNotIn('PRIVATE KEY', output)
        self.assertNotIn('KARIO SYNTHETIC ARCHIVE TEST', output)

    def test_source_bytes_not_in_assessment(self):
        self.assertNotIn('KARIO SYNTHETIC ARCHIVE TEST', repr(self._query()))


if __name__ == '__main__':
    unittest.main()
