"""KARIO v0.4D: offline, *synthetic-only* TSA CRL policy gate.

Extension of the v0.4C RFC3161 cryptographic lab. It checks a pinned
synthetic trust anchor and a complete, current, directly issued CRL. It NEVER
claims archival revocation history, independently trusted time, PIT usability,
legal data rights, or production issuer identity. No network or LSEG SDK.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import re

from cryptography import x509
from asn1crypto import cms
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab

VERSION = 'KARIO_CRL_POLICY_GATE_V0.4D'
_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_MAX_PEM = 1024 * 1024


def _date(dt):
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _read_bounded(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_PEM:
        raise ValueError('missing, linked or oversized certificate/CRL')
    return p.read_bytes()


def _ext(cert, kind):
    return cert.extensions.get_extension_for_class(kind)


def _cms_signer_matches(token_der: bytes, expected_tsa: x509.Certificate) -> bool:
    """Ensure the CRL-checked certificate is the actual CMS signer.

    Checking an arbitrary CA-issued certificate (rather than the token signer)
    could incorrectly report 'not revoked' for a different TSA. The CMS
    signature itself is already checked by the v0.4C OpenSSL verifier.
    """
    token = cms.ContentInfo.load(token_der, strict=True)
    if token['content_type'].native != 'signed_data':
        return False
    signed = token['content']
    infos = signed['signer_infos']
    if len(infos) != 1 or infos[0]['sid'].name != 'issuer_and_serial_number':
        return False
    sid = infos[0]['sid'].chosen
    if (sid['serial_number'].native != expected_tsa.serial_number
            or sid['issuer'].dump() != expected_tsa.issuer.public_bytes()):
        return False
    # The exact expected certificate must appear in the signedData carrier.
    der = expected_tsa.public_bytes(serialization.Encoding.DER)
    return any(c.name == 'certificate' and c.chosen.dump() == der
               for c in signed['certificates'])


class RFC3161CRLPolicyLab:
    """Fail-closed, offline, current-state CRL check over v0.4C lab.

    CRL checking is based on the untrusted local wall clock. The presence of
    a signed, unexpired, complete CRL that does not list the signer cert is
    *not* proof of non-revocation at any historical instant.
    """

    def __init__(self, timestamp_lab: RFC3161OfflineLab, *,
                 crl_pem_path, pinned_root_sha256):
        self.lab = timestamp_lab
        self.crl_path = Path(crl_pem_path)
        self.pin = pinned_root_sha256

    def _policy(self, token_der):
        if not isinstance(self.lab, RFC3161OfflineLab):
            return 'HOLD_CRL_LAB_NOT_CONFIGURED', {}
        if not isinstance(self.pin, str) or not _SHA256.fullmatch(self.pin):
            return 'HOLD_CRL_ROOT_PIN_MISSING', {}
        ca = x509.load_pem_x509_certificate(_read_bounded(self.lab.ca_path))
        tsa = x509.load_pem_x509_certificate(_read_bounded(self.lab.extra_path))
        if ca.fingerprint(hashes.SHA256()).hex() != self.pin:
            return 'HOLD_CRL_ROOT_PIN_MISMATCH', {}
        try:
            if not _cms_signer_matches(token_der, tsa):
                return 'HOLD_CRL_SIGNER_IDENTITY_MISMATCH', {}
        except (ValueError, TypeError, KeyError, IndexError):
            return 'HOLD_CRL_SIGNER_IDENTITY_MISMATCH', {}
        try:
            ca.verify_directly_issued_by(ca)
            tsa.verify_directly_issued_by(ca)
        except (ValueError, TypeError, x509.InvalidVersion):
            return 'HOLD_CRL_CERT_CHAIN', {}
        except Exception:
            return 'HOLD_CRL_CERT_CHAIN', {}
        if ca.subject != ca.issuer or tsa.issuer != ca.subject:
            return 'HOLD_CRL_CERT_CHAIN', {}
        try:
            ca_bc = _ext(ca, x509.BasicConstraints)
            ca_ku = _ext(ca, x509.KeyUsage).value
            tsa_bc = _ext(tsa, x509.BasicConstraints)
            tsa_ku = _ext(tsa, x509.KeyUsage).value
            tsa_eku = _ext(tsa, x509.ExtendedKeyUsage)
            if not (ca_bc.value.ca and ca_ku.key_cert_sign and ca_ku.crl_sign):
                return 'HOLD_CRL_CA_NOT_AUTHORIZED', {}
            if tsa_bc.value.ca or not tsa_ku.digital_signature:
                return 'HOLD_CRL_TSA_NOT_AUTHORIZED', {}
            if not tsa_eku.critical or list(tsa_eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
                return 'HOLD_CRL_TSA_NOT_AUTHORIZED', {}
        except x509.ExtensionNotFound:
            return 'HOLD_CRL_CERT_PROFILE', {}
        at = datetime.now(timezone.utc)  # LOCAL WALL CLOCK ONLY (not an attestation)
        if (not (ca.not_valid_before_utc <= at <= ca.not_valid_after_utc)
                or not (tsa.not_valid_before_utc <= at <= tsa.not_valid_after_utc)):
            return 'HOLD_CRL_CERT_EXPIRED', {}
        try:
            crl = x509.load_pem_x509_crl(_read_bounded(self.crl_path))
        except (ValueError, TypeError):
            return 'HOLD_CRL_MISSING_OR_INVALID', {}
        if crl.issuer != ca.subject:
            return 'HOLD_CRL_ISSUER_MISMATCH', {}
        if not crl.is_signature_valid(ca.public_key()):
            return 'HOLD_CRL_SIGNATURE_INVALID', {}
        try:
            num = _ext(crl, x509.CRLNumber).value.crl_number
            aki = _ext(crl, x509.AuthorityKeyIdentifier).value
            ski = _ext(ca, x509.SubjectKeyIdentifier).value
            if not isinstance(num, int) or num < 0 or aki.key_identifier != ski.digest:
                return 'HOLD_CRL_PROFILE_INVALID', {}
        except x509.ExtensionNotFound:
            return 'HOLD_CRL_PROFILE_INVALID', {}
        # Scope may be incomplete with indirect/delta CRLs. Reject those.
        forbidden = {ExtensionOID.DELTA_CRL_INDICATOR, ExtensionOID.ISSUING_DISTRIBUTION_POINT}
        for e in crl.extensions:
            if e.oid in forbidden or (e.critical and e.oid not in (
                ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)):
                return 'HOLD_CRL_UNSUPPORTED_SCOPE', {}
        # A *complete* CRL must include an explicit nextUpdate.
        if crl.next_update_utc is None or crl.last_update_utc is None:
            return 'HOLD_CRL_FRESHNESS_UNKNOWN', {}
        if not (crl.last_update_utc <= at <= crl.next_update_utc):
            return 'HOLD_CRL_NOT_CURRENT', {}
        if crl.get_revoked_certificate_by_serial_number(tsa.serial_number) is not None:
            return 'HOLD_CRL_SIGNER_REVOKED', {}
        return 'CRL_NOT_LISTED_UNATTESTED', {
            'crl_evidence_checked': True,
            'crl_evaluation_utc': _date(at),
            'crl_number': num,
            'crl_this_update_utc': _date(crl.last_update_utc),
            'crl_next_update_utc': _date(crl.next_update_utc),
            'root_sha256_pin': self.pin,
            'signer_serial_hex': format(tsa.serial_number, 'x'),
            'tsa_revocation_status': 'NOT_LISTED_IN_SUPPLIED_CURRENT_CRL',
            'crl_coverage': 'SYNTHETIC_DIRECT_COMPLETE_CRL_ONLY',
        }

    def assess(self, *, evidence_id, decision_at, token_der,
               request_der, requested_use='LOCAL_SYNTHETIC_TEST') -> dict:
        fields = dict(evidence_id=evidence_id, decision_at=decision_at,
                      token_der=token_der, request_der=request_der,
                      requested_use=requested_use)
        pre = self.lab.assess(**fields) if isinstance(self.lab, RFC3161OfflineLab) else {
            'status': 'HOLD_CRL_LAB_NOT_CONFIGURED', 'token_crypto_verified': False}
        response = {
            **pre,
            'crl_gate_version': VERSION,
            'crl_evidence_checked': False,
            'tsa_revocation_status': 'UNKNOWN',
            'trusted_time_verified': False,
            'external_attestation_verified': False,
            'pit_certified': False,
            'rights_legally_cleared': False,
        }
        if pre.get('status') != 'RFC3161_CRYPTO_VALID_UNATTESTED':
            return response
        try:
            status, props = self._policy(token_der)
        except (ValueError, TypeError, OSError, OverflowError):
            status, props = 'HOLD_CRL_MISSING_OR_INVALID', {}
        except Exception:
            status, props = 'HOLD_CRL_POLICY_ERROR', {}
        response.update(props)
        response['status'] = status
        response['notice'] = ('Current synthetic CRL checking, not an independent historical '
                              'revocation proof, TSA trust certification, source availability, '
                              'legal rights, or PIT certification.')
        return response
