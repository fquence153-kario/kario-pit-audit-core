"""v0.4D offline synthetic CRL policy demo; no outside TSA or LSEG data."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import json
import shutil
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab, entry_commitment
from kario_pit.attestation.crl_gate_v04d import RFC3161CRLPolicyLab
from kario_pit.registry import EvidenceLedger
from tsa_lab_fixture_v04c import POLICY_OID, make_fixture
from tsa_crl_fixture_v04d import make_synthetic_crl


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ledger', required=True)
    opts = p.parse_args()
    path = Path(opts.ledger)
    if path.exists() or path.is_symlink():
        p.error('Refusing to overwrite existing ledger')
    openssl = shutil.which('openssl')
    if not openssl:
        p.error('OpenSSL CLI missing, offline CRL demo cannot run')
    ledger = EvidenceLedger(path)
    row = ledger.append(
        evidence_id='SYN-CRL-DEMO', provider_id='MOCK', source_record_id='CRL-DEMO',
        revision_id='R1', rights_class='SYNTHETIC_PUBLIC',
        registered_latency_seconds=0, content=b'KARIO SYNTHETIC CRL DEMO CONTENT',
        source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat())
    decision = (datetime.now(timezone.utc)+timedelta(seconds=90)).isoformat()
    with tempfile.TemporaryDirectory(prefix='kario_synthetic_crl_') as td:
        root = Path(td)
        fixture = make_fixture(root/'keys', openssl_executable=openssl, commitment=entry_commitment(row))
        pin = x509.load_pem_x509_certificate(fixture['ca'].read_bytes()).fingerprint(hashes.SHA256()).hex()
        ca_key = fixture['ca'].parent/'ca.key'
        current_crl = make_synthetic_crl(fixture['ca'], ca_key, fixture['tsa'], root/'current.crl')
        revoked_crl = make_synthetic_crl(fixture['ca'], ca_key, fixture['tsa'], root/'revoked.crl', revoked=True)
        lab = RFC3161OfflineLab(path, synthetic_fixture_ids={'SYN-CRL-DEMO'},
            root_ca_pem_path=fixture['ca'], extra_cert_pem_path=fixture['tsa'],
            allowed_policy_oids={POLICY_OID}, openssl_executable=openssl)
        input_args = dict(evidence_id='SYN-CRL-DEMO', decision_at=decision,
            token_der=fixture['token'].read_bytes(), request_der=fixture['request'].read_bytes())
        good = RFC3161CRLPolicyLab(lab, crl_pem_path=current_crl,
            pinned_root_sha256=pin).assess(**input_args)
        revoked = RFC3161CRLPolicyLab(lab, crl_pem_path=revoked_crl,
            pinned_root_sha256=pin).assess(**input_args)
        unpinned = RFC3161CRLPolicyLab(lab, crl_pem_path=current_crl,
            pinned_root_sha256='0'*64).assess(**input_args)
        cloud = RFC3161CRLPolicyLab(lab, crl_pem_path=current_crl,
            pinned_root_sha256=pin).assess(**input_args, requested_use='CLOUD_PROCESSING')
    report = {
        'ledger': str(path), 'ledger_verification': ledger.verify(),
        'current_crl_not_listed_unattested': good,
        'revoked_signer_denied': revoked,
        'untrusted_root_denied': unpinned,
        'cloud_use_denied': cloud,
        'notice': 'SYNTHETIC, EPHEMERAL CA/TSA/CRL. No independently trusted time or historical PIT proof.',
    }
    assert good['status'] == 'CRL_NOT_LISTED_UNATTESTED' and good['token_crypto_verified']
    assert not good['trusted_time_verified'] and not good['pit_certified']
    assert revoked['status'] == 'HOLD_CRL_SIGNER_REVOKED'
    assert unpinned['status'] == 'HOLD_CRL_ROOT_PIN_MISMATCH'
    assert cloud['status'] == 'HOLD_INVALID_USE'
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
