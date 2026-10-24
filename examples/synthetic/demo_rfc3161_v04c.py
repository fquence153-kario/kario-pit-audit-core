"""Offline RFC3161 synthetic demonstration. Does not make a real TSA claim."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile

from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab, entry_commitment
from kario_pit.registry import EvidenceLedger
from tsa_lab_fixture_v04c import POLICY_OID, make_fixture


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--openssl', default='openssl')
    options = parser.parse_args()
    path = Path(options.ledger)
    if path.exists() or path.is_symlink():
        parser.error('Refusing to overwrite existing ledger')
    exe = shutil.which(options.openssl)
    if not exe:
        parser.error('OpenSSL CLI unavailable. v0.4C fails closed without it.')
    now = datetime.now(timezone.utc)
    ledger = EvidenceLedger(path)
    row = ledger.append(
        evidence_id='SYN-RFC3161-01', provider_id='MOCK',
        source_record_id='RFC3161-LAB', revision_id='R1',
        rights_class='SYNTHETIC_PUBLIC', content=b'ONLY SYNTHETIC KARIO INPUT',
        registered_latency_seconds=0, source_published_at=iso(now - timedelta(minutes=1)))
    observed = datetime.fromisoformat(row['recorded_at_utc'].replace('Z', '+00:00'))
    decision = iso(observed + timedelta(seconds=90))
    with tempfile.TemporaryDirectory(prefix='kario_tsa_synthetic_') as temp:
        f = make_fixture(temp, openssl_executable=exe, commitment=entry_commitment(row))
        verifier = RFC3161OfflineLab(
            path, synthetic_fixture_ids={'SYN-RFC3161-01'},
            root_ca_pem_path=f['ca'], extra_cert_pem_path=f['tsa'],
            allowed_policy_oids={POLICY_OID}, openssl_executable=exe)
        fields = dict(evidence_id='SYN-RFC3161-01', decision_at=decision,
                      token_der=f['token'].read_bytes(), request_der=f['request'].read_bytes())
        good = verifier.assess(**fields)
        no_time = verifier.assess(**{**fields, 'decision_at': iso(observed - timedelta(seconds=1))})
        denied = verifier.assess(**fields, requested_use='CLOUD_PROCESSING')
        altered = verifier.assess(**{**fields, 'token_der': fields['token_der'][:-3] + b'bad'})
    report = {
        'ledger': str(path),
        'ledger_verification': ledger.verify(),
        'synthetic_token_valid_unattested': good,
        'decision_before_local_receipt_denied': no_time,
        'cloud_use_denied': denied,
        'altered_token_denied': altered,
        'notice': ('SELF-SIGNED LAB CA, NO REVOCATION OR EXTERNAL HISTORY CHECK. '
                   'Token validation is NOT trusted historical time, availability or PIT certification.'),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not (good['status'] == 'RFC3161_CRYPTO_VALID_UNATTESTED'
            and good['token_crypto_verified'] is True
            and good['trusted_time_verified'] is False
            and good['pit_certified'] is False):
        raise RuntimeError('v0.4C synthetic demonstration did not meet its invariant')


if __name__ == '__main__':
    main()
