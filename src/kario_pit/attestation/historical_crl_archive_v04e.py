"""v0.4E offline *synthetic-only* historical CRL snapshot consistency gate.

CA/TSA/CRL cryptography + a pinned LOCAL archive manifest are checked at
an explicit hypothetical decision time. 'First observed' is an OPERATOR
ASSERTION, not an authenticated historic receipt. No LSEG, network, OCSP,
production trust, trusted time, legal clearance, or PIT certification.
"""
from __future__ import annotations

from datetime import timezone
from hashlib import sha256
import json
from pathlib import Path
import re

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from kario_pit.audit.time_gate import parse_utc
from kario_pit.attestation.rfc3161_offline import RFC3161OfflineLab
from kario_pit.attestation.crl_gate_v04d import _cms_signer_matches

VERSION = 'KARIO_HISTORICAL_CRL_ARCHIVE_LAB_V0.4E'
MANIFEST_VERSION = 'KARIO_SYNTHETIC_CRL_ARCHIVE_MANIFEST_V0.4E'
_RE_SHA = re.compile(r'^[0-9a-f]{64}$')
_RE_ID = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
_FIELDS = frozenset({
    'manifest_version', 'archive_id', 'evidence_id', 'ledger_entry_hash',
    'crl_sha256', 'tsa_cert_sha256', 'ca_cert_sha256',
    'token_sha256', 'request_sha256', 'first_observed_at_utc',
    'time_basis',
})
_MAX_MANIFEST = 8192
_MAX_CRL = 1024 * 1024
_MAX_CERT = 1024 * 1024


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _read_regular_file(path, max_bytes):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError('not a regular file')
    n = p.stat().st_size
    if not 0 < n <= max_bytes:
        raise ValueError('missing or oversized input')
    return p.read_bytes()


def make_local_manifest(*, archive_id, evidence_id, ledger_entry_hash,
                        crl_bytes, tsa_cert_bytes, ca_cert_bytes,
                        token_der, request_der, first_observed_at_utc):
    """Build a demonstrative LOCAL claim; not an independent observation."""
    if not isinstance(archive_id, str) or not _RE_ID.fullmatch(archive_id):
        raise ValueError('invalid archive ID')
    if not isinstance(evidence_id, str) or not _RE_ID.fullmatch(evidence_id):
        raise ValueError('invalid evidence ID')
    if not isinstance(ledger_entry_hash, str) or not _RE_SHA.fullmatch(ledger_entry_hash):
        raise ValueError('invalid ledger entry hash')
    when = parse_utc(first_observed_at_utc)
    return {
        'manifest_version': MANIFEST_VERSION,
        'archive_id': archive_id,
        'evidence_id': evidence_id,
        'ledger_entry_hash': ledger_entry_hash,
        'crl_sha256': sha256(crl_bytes).hexdigest(),
        'tsa_cert_sha256': sha256(tsa_cert_bytes).hexdigest(),
        'ca_cert_sha256': sha256(ca_cert_bytes).hexdigest(),
        'token_sha256': sha256(token_der).hexdigest(),
        'request_sha256': sha256(request_der).hexdigest(),
        'first_observed_at_utc': _iso(when),
        'time_basis': 'LOCAL_OPERATOR_ASSERTION_UNATTESTED',
    }


def manifest_json_bytes(manifest):
    """Canonical JSON bytes. A local pin detects changes, not backdating."""
    return json.dumps(manifest, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


class HistoricalCRLArchiveLab:
    """Reconcile a pinned synthetic archive as-of decision; never certify PIT.

    This is NOT historic PKI path validation. In particular, the upstream
    v0.4C OpenSSL verifier still uses local wall-clock certificate validation.
    Manifest observations are self-reported; they may be backdated.
    """

    def __init__(self, timestamp_lab: RFC3161OfflineLab, *, crl_pem_path,
                 manifest_path, expected_manifest_sha256, pinned_root_sha256):
        self.lab = timestamp_lab
        self.crl = Path(crl_pem_path)
        self.manifest = Path(manifest_path)
        self.expected_manifest_sha256 = expected_manifest_sha256
        self.pin = pinned_root_sha256

    def assess(self, *, evidence_id, decision_at, token_der, request_der,
               requested_use='LOCAL_SYNTHETIC_TEST'):
        base = {
            'archive_gate_version': VERSION,
            'status': 'HOLD_ARCHIVE_UNCHECKED',
            'token_crypto_verified': False,
            'local_archive_consistency_pass': False,
            'historical_status_independently_attested': False,
            'trusted_time_verified': False,
            'external_attestation_verified': False,
            'pit_certified': False,
            'rights_legally_cleared': False,
        }
        if not isinstance(self.lab, RFC3161OfflineLab):
            return {**base, 'status': 'HOLD_ARCHIVE_LAB_UNAVAILABLE'}
        pre = self.lab.assess(evidence_id=evidence_id, decision_at=decision_at,
                              token_der=token_der, request_der=request_der,
                              requested_use=requested_use)
        result = {**pre, **base, 'token_crypto_verified': pre.get('token_crypto_verified') is True}
        if pre.get('status') != 'RFC3161_CRYPTO_VALID_UNATTESTED':
            result['status'] = pre.get('status', 'HOLD_ARCHIVE_PRECHECK')
            return result

        def hold(status):
            return {**result, 'status': status}

        if not all(isinstance(v, str) and _RE_SHA.fullmatch(v)
                   for v in (self.expected_manifest_sha256, self.pin)):
            return hold('HOLD_ARCHIVE_PIN_MISSING')
        try:
            decision = parse_utc(decision_at)
            ca_bytes = _read_regular_file(self.lab.ca_path, _MAX_CERT)
            tsa_bytes = _read_regular_file(self.lab.extra_path, _MAX_CERT)
            crl_bytes = _read_regular_file(self.crl, _MAX_CRL)
            manifest_bytes = _read_regular_file(self.manifest, _MAX_MANIFEST)
        except (ValueError, TypeError, OSError):
            return hold('HOLD_ARCHIVE_INPUT_UNAVAILABLE')
        if sha256(manifest_bytes).hexdigest() != self.expected_manifest_sha256:
            return hold('HOLD_ARCHIVE_MANIFEST_CHANGED')
        try:
            manifest = json.loads(manifest_bytes.decode('utf-8'))
            if type(manifest) is not dict or frozenset(manifest) != _FIELDS:
                return hold('HOLD_ARCHIVE_MANIFEST_INVALID')
            if (manifest['manifest_version'] != MANIFEST_VERSION
                    or manifest['time_basis'] != 'LOCAL_OPERATOR_ASSERTION_UNATTESTED'
                    or type(manifest['archive_id']) is not str
                    or not _RE_ID.fullmatch(manifest['archive_id'])
                    or type(manifest['evidence_id']) is not str
                    or manifest['evidence_id'] != evidence_id):
                return hold('HOLD_ARCHIVE_MANIFEST_INVALID')
            # Reject alternate/noncanonical JSON representations: no signed JSON
            # semantics or whitespace normalisation ambiguities in this lab.
            if manifest_bytes != manifest_json_bytes(manifest):
                return hold('HOLD_ARCHIVE_MANIFEST_NONCANONICAL')
            for key in ('ledger_entry_hash', 'crl_sha256', 'tsa_cert_sha256',
                        'ca_cert_sha256', 'token_sha256', 'request_sha256'):
                if type(manifest[key]) is not str or not _RE_SHA.fullmatch(manifest[key]):
                    return hold('HOLD_ARCHIVE_MANIFEST_INVALID')
            files = {'crl_sha256': crl_bytes, 'tsa_cert_sha256': tsa_bytes,
                     'ca_cert_sha256': ca_bytes, 'token_sha256': token_der,
                     'request_sha256': request_der}
            if (manifest['ledger_entry_hash'] != pre.get('ledger_entry_hash')
                    or any(sha256(b).hexdigest() != manifest[k] for k, b in files.items())):
                return hold('HOLD_ARCHIVE_BINDING_MISMATCH')
            observed = parse_utc(manifest['first_observed_at_utc'])
            if _iso(observed) != manifest['first_observed_at_utc']:
                return hold('HOLD_ARCHIVE_MANIFEST_NONCANONICAL')
        except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
            return hold('HOLD_ARCHIVE_MANIFEST_INVALID')
        if observed > decision:
            return hold('HOLD_ARCHIVE_OBSERVED_AFTER_DECISION')
        try:
            ca = x509.load_pem_x509_certificate(ca_bytes)
            tsa = x509.load_pem_x509_certificate(tsa_bytes)
            crl = x509.load_pem_x509_crl(crl_bytes)
        except ValueError:
            return hold('HOLD_ARCHIVE_CERT_OR_CRL_INVALID')
        if ca.fingerprint(hashes.SHA256()).hex() != self.pin:
            return hold('HOLD_ARCHIVE_ROOT_PIN_MISMATCH')
        try:
            if not _cms_signer_matches(token_der, tsa):
                return hold('HOLD_ARCHIVE_SIGNER_MISMATCH')
            ca.verify_directly_issued_by(ca)
            tsa.verify_directly_issued_by(ca)
        except Exception:
            return hold('HOLD_ARCHIVE_CERT_CHAIN')
        if tsa.issuer != ca.subject or ca.subject != ca.issuer:
            return hold('HOLD_ARCHIVE_CERT_CHAIN')
        try:
            ca_bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
            ca_ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
            tsa_bc = tsa.extensions.get_extension_for_class(x509.BasicConstraints).value
            tsa_ku = tsa.extensions.get_extension_for_class(x509.KeyUsage).value
            tsa_eku = tsa.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if (not ca_bc.ca or not ca_ku.key_cert_sign or not ca_ku.crl_sign
                    or tsa_bc.ca or not tsa_ku.digital_signature
                    or not tsa_eku.critical
                    or list(tsa_eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]):
                return hold('HOLD_ARCHIVE_CERT_PROFILE')
            gen_time = parse_utc(pre['gen_time_utc'])
            # No retroactive validation for expired certs from upstream v0.4C.
            if not (ca.not_valid_before_utc <= gen_time <= ca.not_valid_after_utc
                    and tsa.not_valid_before_utc <= gen_time <= tsa.not_valid_after_utc):
                return hold('HOLD_ARCHIVE_CERT_TIME')
        except (KeyError, ValueError, x509.ExtensionNotFound):
            return hold('HOLD_ARCHIVE_CERT_PROFILE')
        if crl.issuer != ca.subject or not crl.is_signature_valid(ca.public_key()):
            return hold('HOLD_ARCHIVE_CRL_SIGNATURE_OR_ISSUER')
        try:
            num = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            if type(num) is not int or num < 0 or aki != ski:
                return hold('HOLD_ARCHIVE_CRL_PROFILE')
            for ext in crl.extensions:
                if (ext.oid in (ExtensionOID.DELTA_CRL_INDICATOR,
                                ExtensionOID.ISSUING_DISTRIBUTION_POINT)
                    or (ext.critical and ext.oid not in (
                        ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER))):
                    return hold('HOLD_ARCHIVE_CRL_SCOPE')
        except x509.ExtensionNotFound:
            return hold('HOLD_ARCHIVE_CRL_PROFILE')
        if crl.next_update_utc is None or crl.last_update_utc is None:
            return hold('HOLD_ARCHIVE_CRL_WINDOW_UNDEFINED')
        if observed < crl.last_update_utc:
            return hold('HOLD_ARCHIVE_OBSERVED_BEFORE_ISSUED')
        if not (crl.last_update_utc <= decision < crl.next_update_utc):
            return hold('HOLD_ARCHIVE_CRL_NOT_VALID_AT_DECISION')
        # Fail closed on ANY listing, including a revocation issued later.
        if crl.get_revoked_certificate_by_serial_number(tsa.serial_number) is not None:
            return hold('HOLD_ARCHIVE_SIGNER_LISTED')
        return {
            **result,
            'status': 'HISTORICAL_CRL_SNAPSHOT_CONSISTENT_UNATTESTED',
            'local_archive_consistency_pass': True,
            'manifest_sha256': self.expected_manifest_sha256,
            'crl_number': num,
            'crl_this_update_utc': _iso(crl.last_update_utc),
            'crl_next_update_utc': _iso(crl.next_update_utc),
            'operator_claimed_first_observed_utc': _iso(observed),
            'crl_coverage': 'SYNTHETIC_DIRECT_COMPLETE_ONLY',
            'historical_status_independently_attested': False,
            'notice': ('Local archive hashes + CRL cryptography + as-of window are '
                       'consistent. Operator-observed time and trust anchor are NOT '
                       'independently authenticated. No historical PIT, TSA trust, '
                       'source availability or licensing assertion.'),
        }
