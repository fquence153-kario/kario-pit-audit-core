"""v0.4C offline RFC 3161 *laboratory* verifier. Synthetic fixtures only.

OpenSSL verifies CMS signature, certificate chain, and request/token imprint;
asn1crypto verifies and interprets the structured timestamp semantics. The
explicit trust anchor is caller-provided; it has NOT been independently vetted.
No CRL/OCSP, archival validation, independently established request time,
content availability, source authorization, or production PIT certification.
Any check failure returns HOLD. Never stores source bytes or uses the network.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from kario_pit.audit.time_gate import parse_utc
from kario_pit.registry import EvidenceLedger

VERSION = 'KARIO_RFC3161_OFFLINE_LAB_V0.4C'
COMMITMENT_VERSION = 'KARIO_LEDGER_ENTRY_COMMITMENT_V0.4C'
_SHA = re.compile(r'^[0-9a-f]{64}$')
_ID = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
_OID = re.compile(r'^[0-9]+(?:\.[0-9]+){2,}$')
_MAX_DER = 256 * 1024


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _hold(status: str, **kw) -> dict:
    return {
        'verifier_version': VERSION,
        'status': status,
        'token_crypto_verified': False,
        'token_time_gate_pass': False,
        'trusted_time_verified': False,
        'external_attestation_verified': False,
        'pit_certified': False,
        'rights_legally_cleared': False,
        **kw,
    }


def entry_commitment(row: dict) -> bytes:
    """Domain-separated deterministic commitment for one *verified* ledger row.

    This is an authenticated-binding input only when the caller has separately
    verified the ledger and the original content hash. Never assume a local
    ledger or this commitment proves historical time or user availability.
    """
    if not isinstance(row, dict) or not {'entry_hash', 'payload'} <= row.keys():
        raise ValueError('bad evidence row')
    p = row['payload']
    if not isinstance(p, dict):
        raise ValueError('bad evidence payload')
    for value in (row['entry_hash'], p.get('content_sha256')):
        if not isinstance(value, str) or not _SHA.fullmatch(value):
            raise ValueError('invalid hash')
    for key in ('evidence_id', 'revision_id', 'provider_id', 'source_record_id'):
        if not isinstance(p.get(key), str) or not _ID.fullmatch(p[key]):
            raise ValueError('invalid identifier')
    obj = {
        'schema_version': COMMITMENT_VERSION,
        'evidence_id': p['evidence_id'],
        'revision_id': p['revision_id'],
        'provider_id': p['provider_id'],
        'source_record_id': p['source_record_id'],
        'entry_hash': row['entry_hash'],
        'content_sha256': p['content_sha256'],
    }
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _inspect_token_request(token_der: bytes, request_der: bytes, digest: bytes,
                           allowed_policies: frozenset[str]) -> dict:
    """Parse untrusted ASN.1; returned fields must still be signature verified."""
    from asn1crypto import cms, tsp
    ci = cms.ContentInfo.load(token_der, strict=True)
    if ci['content_type'].native != 'signed_data':
        raise ValueError('token is not CMS signedData')
    si = ci['content']
    enc = si['encap_content_info']
    if enc['content_type'].dotted != '1.2.840.113549.1.9.16.1.4':
        raise ValueError('token does not contain TSTInfo')
    # asn1crypto represents this as a parsable OCTET STRING.
    raw = enc['content'].contents
    tst = tsp.TSTInfo.load(raw, strict=True)
    req = tsp.TimeStampReq.load(request_der, strict=True)
    if req['version'].native != 'v1' or tst['version'].native != 'v1':
        raise ValueError('unsupported timestamp version')
    a = req['message_imprint']
    b = tst['message_imprint']
    if (a['hash_algorithm']['algorithm'].native != 'sha256'
            or b['hash_algorithm']['algorithm'].native != 'sha256'):
        raise ValueError('only SHA-256 message imprints accepted')
    if a['hashed_message'].native != digest or b['hashed_message'].native != digest:
        raise ValueError('request/token hash mismatch')
    if not bool(req['cert_req'].native):
        raise ValueError('certificate requested flag required')
    nonce = req['nonce'].native
    if type(nonce) is not int or nonce <= 0 or tst['nonce'].native != nonce:
        raise ValueError('nonce absent or mismatch')
    # Request policy may be absent, token policy must be allowlisted.
    policy = tst['policy'].dotted
    if policy not in allowed_policies:
        raise ValueError('token policy not allowlisted')
    if req['req_policy'].native is not None and req['req_policy'].dotted != policy:
        raise ValueError('request policy mismatch')
    gen = tst['gen_time'].native
    if not isinstance(gen, datetime) or gen.tzinfo is None:
        raise ValueError('genTime is not UTC')
    # Explicit accuracy required to form an upper bound in this pilot.
    acc = tst['accuracy'].native
    if not isinstance(acc, dict):
        raise ValueError('accuracy missing')
    sec, ms, us = acc.get('seconds') or 0, acc.get('millis') or 0, acc.get('micros') or 0
    if (any(type(n) is not int or n < 0 for n in (sec, ms, us))
            or ms > 999 or us > 999 or sec > 86400):
        raise ValueError('accuracy invalid')
    if all(acc.get(k) is None for k in ('seconds', 'millis', 'micros')):
        raise ValueError('accuracy unspecified')
    return {
        'nonce': nonce,
        'policy_oid': policy,
        'serial_number': str(tst['serial_number'].native),
        'gen_time_utc': _iso(gen),
        'gen_time_upper_utc': _iso(gen + timedelta(seconds=sec, milliseconds=ms, microseconds=us)),
        'message_imprint_sha256': digest.hex(),
    }


class RFC3161OfflineLab:
    """Strict, synthetic-only, fail-closed verifier using an explicit CA file.

    Requires separately installed OpenSSL CLI (3.x recommended). The private
    keys or any third-party source bytes are never supplied to this class.
    """

    def __init__(self, ledger_path, *, synthetic_fixture_ids,
                 root_ca_pem_path, extra_cert_pem_path,
                 allowed_policy_oids, openssl_executable='openssl'):
        self.ledger = EvidenceLedger(ledger_path)
        self.allowed_ids = frozenset(synthetic_fixture_ids)
        self.ca_path = Path(root_ca_pem_path)
        self.extra_path = Path(extra_cert_pem_path)
        self.policies = frozenset(allowed_policy_oids)
        self.openssl = str(openssl_executable)

    def assess(self, *, evidence_id, decision_at, token_der,
               request_der, requested_use='LOCAL_SYNTHETIC_TEST') -> dict:
        result = _hold('HOLD_INVALID_INPUT', evidence_id=evidence_id)
        try:
            decision = parse_utc(decision_at)
            if (not isinstance(evidence_id, str) or not _ID.fullmatch(evidence_id)
                    or not self.allowed_ids or evidence_id not in self.allowed_ids):
                return _hold('HOLD_FIXTURE_NOT_ALLOWED', evidence_id=evidence_id)
            if requested_use != 'LOCAL_SYNTHETIC_TEST':
                return _hold('HOLD_INVALID_USE', evidence_id=evidence_id)
            if not self.policies or any(not isinstance(p, str) or not _OID.fullmatch(p)
                                        for p in self.policies):
                return _hold('HOLD_POLICY_NOT_CONFIGURED', evidence_id=evidence_id)
            if (type(token_der) is not bytes or type(request_der) is not bytes
                    or not (1 <= len(token_der) <= _MAX_DER)
                    or not (1 <= len(request_der) <= _MAX_DER)):
                return result
            try:
                rows = self.ledger._verify_and_load()
            except Exception:
                return _hold('HOLD_LEDGER_INTEGRITY', evidence_id=evidence_id)
            hits = [x for x in rows if x['payload']['evidence_id'] == evidence_id]
            if len(hits) != 1:
                return _hold('HOLD_EVIDENCE_NOT_FOUND', evidence_id=evidence_id)
            row = hits[0]
            if row['payload']['rights_class'] != 'SYNTHETIC_PUBLIC':
                return _hold('HOLD_RIGHTS_RESTRICTED', evidence_id=evidence_id)
            gate = self.ledger.audit(evidence_id, decision_at)
            if gate.get('status') != 'TIME_GATE_PASS_UNVERIFIED':
                return _hold('HOLD_LOCAL_TIME_GATE', evidence_id=evidence_id,
                             underlying_gate=gate.get('status'))
            digest = sha256(entry_commitment(row)).digest()
            try:
                proof = _inspect_token_request(token_der, request_der, digest, self.policies)
            except (ValueError, TypeError, KeyError, OverflowError, IndexError) as exc:
                return _hold('HOLD_TOKEN_SEMANTICS', evidence_id=evidence_id,
                             diagnostic=type(exc).__name__)
            # Non-null issuer-supplied accuracy; its upper bound must fit.
            if parse_utc(proof['gen_time_upper_utc']) > decision:
                return _hold('HOLD_TOKEN_AFTER_DECISION', evidence_id=evidence_id, **proof)
            if parse_utc(proof['gen_time_upper_utc']) < parse_utc(row['recorded_at_utc']):
                return _hold('HOLD_TOKEN_BEFORE_LEDGER_RECEIPT', evidence_id=evidence_id)
            if (not self.ca_path.is_file() or not self.extra_path.is_file()
                    or not self.ca_path.read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')):
                return _hold('HOLD_TRUST_ANCHOR_MISSING', evidence_id=evidence_id)
            exe = shutil.which(self.openssl)
            if exe is None:
                return _hold('HOLD_OPENSSL_UNAVAILABLE', evidence_id=evidence_id)
            with tempfile.TemporaryDirectory(prefix='kario_rfc3161_') as temp:
                tmp = Path(temp)
                (tmp / 'token.der').write_bytes(token_der)
                (tmp / 'request.tsq').write_bytes(request_der)
                # -CAfile is explicitly provided; never auto-trust a cert from
                # a token. CLI verifies CMS sig, signer EKU & chain + nonce.
                cmd = [exe, 'ts', '-verify', '-token_in', '-in', str(tmp / 'token.der'),
                       '-queryfile', str(tmp / 'request.tsq'),
                       '-CAfile', str(self.ca_path), '-untrusted', str(self.extra_path),
                       '-auth_level', '2']
                try:
                    completed = subprocess.run(cmd, capture_output=True,
                                               text=True, timeout=15, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    return _hold('HOLD_VERIFIER_EXECUTION', evidence_id=evidence_id)
                if completed.returncode != 0 or 'Verification: OK' not in completed.stdout:
                    return _hold('HOLD_SIGNATURE_OR_CHAIN', evidence_id=evidence_id)
            return {
                **_hold('RFC3161_CRYPTO_VALID_UNATTESTED', evidence_id=evidence_id),
                **proof,
                'token_crypto_verified': True,
                'token_time_gate_pass': True,
                'ledger_entry_hash': row['entry_hash'],
                'notice': 'LAB CA only: no revocation/independent time or availability proof',
            }
        except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
            return _hold('HOLD_VERIFICATION_ERROR', evidence_id=evidence_id,
                         diagnostic=type(exc).__name__)
