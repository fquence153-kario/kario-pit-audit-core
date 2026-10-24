"""Offline synthetic CRL creation. Private keys exist only in temp test dirs."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def make_synthetic_crl(ca_cert_path, ca_key_path, tsa_cert_path, output_path, *,
                       revoked=False, stale=False, future=False, tamper=False,
                       omit_aki=False, omit_number=False, limited_scope=False):
    ca = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    tsa = x509.load_pem_x509_certificate(Path(tsa_cert_path).read_bytes())
    key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    if stale:
        beginning, ending = now-timedelta(days=4), now-timedelta(days=2)
    elif future:
        beginning, ending = now+timedelta(hours=1), now+timedelta(days=1)
    else:
        beginning, ending = now-timedelta(minutes=3), now+timedelta(days=1)
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
         .last_update(beginning).next_update(ending))
    if not omit_aki:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
    if not omit_number:
        b = b.add_extension(x509.CRLNumber(1), False)
    if limited_scope:
        b = b.add_extension(x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=True,
            only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=False, only_contains_attribute_certs=False), True)
    if revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder()
            .serial_number(tsa.serial_number)
            .revocation_date(now-timedelta(minutes=2)).build())
    signed = b.sign(private_key=key, algorithm=hashes.SHA256())
    if tamper:
        der = bytearray(signed.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        try:
            signed = x509.load_der_x509_crl(bytes(der))
        except ValueError:
            raise RuntimeError('Unable to create syntactically valid tampered CRL')
    dest = Path(output_path)
    dest.write_bytes(signed.public_bytes(serialization.Encoding.PEM))
    return dest
