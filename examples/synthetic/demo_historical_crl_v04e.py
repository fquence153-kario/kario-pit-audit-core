"""Local synthetic CRL archive demo, NEVER real historical TSA or vendor data."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import argparse
import json
import shutil
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from kario_pit.registry import EvidenceLedger
from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab, entry_commitment
from kario_pit.attestation.historical_crl_archive_v04e import (
    HistoricalCRLArchiveLab, make_local_manifest, manifest_json_bytes,
)
from tsa_lab_fixture_v04c import make_fixture, POLICY_OID
from tsa_crl_fixture_v04d import make_synthetic_crl


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ledger', required=True)
    args = p.parse_args()
    ledger_path = Path(args.ledger)
    if ledger_path.is_symlink() or ledger_path.exists():
        p.error('Refusing to overwrite ledger')
    openssl = shutil.which('openssl')
    if not openssl:
        p.error('OpenSSL CLI required')
    ledger = EvidenceLedger(ledger_path)
    row = ledger.append(evidence_id='SYN-ARCHIVE-DEMO', provider_id='MOCK',
        source_record_id='HISTORICAL-DEMO', revision_id='R1',
        rights_class='SYNTHETIC_PUBLIC', registered_latency_seconds=0,
        source_published_at=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat(),
        content=b'KARIO SYNTHETIC LOCAL ARCHIVE DATA ONLY')
    decision = (datetime.now(timezone.utc)+timedelta(seconds=120)).isoformat()
    with tempfile.TemporaryDirectory(prefix='kario_v04e_synthetic_') as td:
        folder = Path(td)
        f = make_fixture(folder/'keys', openssl_executable=openssl,
                         commitment=entry_commitment(row))
        crl = make_synthetic_crl(f['ca'], f['ca'].parent/'ca.key',
                                 f['tsa'], folder/'current.crl')
        revoked_crl = make_synthetic_crl(f['ca'], f['ca'].parent/'ca.key',
                                         f['tsa'], folder/'revoked.crl', revoked=True)
        pin = x509.load_pem_x509_certificate(f['ca'].read_bytes()).fingerprint(hashes.SHA256()).hex()
        lab = RFC3161OfflineLab(ledger_path, synthetic_fixture_ids={'SYN-ARCHIVE-DEMO'},
              root_ca_pem_path=f['ca'], extra_cert_pem_path=f['tsa'],
              allowed_policy_oids={POLICY_OID}, openssl_executable=openssl)
        payload = dict(evidence_id='SYN-ARCHIVE-DEMO', decision_at=decision,
                       token_der=f['token'].read_bytes(), request_der=f['request'].read_bytes())

        def evaluate(crl_file, observed_at, filename, **extra):
            m = make_local_manifest(
                archive_id='SYN-ARCHIVE-DEMO', evidence_id=payload['evidence_id'],
                ledger_entry_hash=row['entry_hash'], crl_bytes=crl_file.read_bytes(),
                tsa_cert_bytes=f['tsa'].read_bytes(), ca_cert_bytes=f['ca'].read_bytes(),
                token_der=payload['token_der'], request_der=payload['request_der'],
                first_observed_at_utc=observed_at)
            path = folder/filename
            raw = manifest_json_bytes(m)
            path.write_bytes(raw)
            gate = HistoricalCRLArchiveLab(lab, crl_pem_path=crl_file,
                manifest_path=path, expected_manifest_sha256=sha256(raw).hexdigest(),
                pinned_root_sha256=pin)
            return gate.assess(**{**payload, **extra})

        good = evaluate(crl, datetime.now(timezone.utc).isoformat(), 'ok.json')
        future = evaluate(crl, (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
                          'future.json')
        revoked = evaluate(revoked_crl, datetime.now(timezone.utc).isoformat(), 'revoked.json')
        cloud = evaluate(crl, datetime.now(timezone.utc).isoformat(),
                         'cloud.json', requested_use='CLOUD_PROCESSING')

    report = dict(
        ledger=str(ledger_path), ledger_verification=ledger.verify(),
        local_archive_consistent_unattested=good,
        later_operator_claim_denied=future,
        revoked_signer_denied=revoked,
        cloud_use_denied=cloud,
        notice='Synthetic lab only. Local operator receipt can be backdated. No real historic TSA/PIT/rights proof.',
    )
    assert good['status'] == 'HISTORICAL_CRL_SNAPSHOT_CONSISTENT_UNATTESTED'
    assert good['local_archive_consistency_pass'] is True
    assert good['trusted_time_verified'] is False and good['pit_certified'] is False
    assert future['status'] == 'HOLD_ARCHIVE_OBSERVED_AFTER_DECISION'
    assert revoked['status'] == 'HOLD_ARCHIVE_SIGNER_LISTED'
    assert cloud['status'] == 'HOLD_INVALID_USE'
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
