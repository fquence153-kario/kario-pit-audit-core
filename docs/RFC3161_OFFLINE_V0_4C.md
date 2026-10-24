# KARIO PIT Audit Core v0.4C — RFC 3161 Offline Synthetic Lab

**PRE-RELEASE. NOT a production time-stamp authority or PIT certification engine.**

## Scope

This additive module uses:

- `asn1crypto` to decode and compare the ASN.1 RFC 3161 request and token, including SHA-256 imprint, nonce, TSA policy OID, `genTime`, and the signed accuracy upper bound.
- OpenSSL CLI `ts -verify` to check the CMS signature, TSA signing certificate chain, request/token correspondence and related cryptographic requirements against an *explicitly configured* CA certificate.
- KARIO v0.2 `EvidenceLedger` metadata hash chain and v0.1 local time gate for synthetic-only scenarios.

The RFC 3161 imprint here commits to `(entry_hash, content_sha256, evidence_id, revision_id, provider_id, source_record_id)` in a canonical JSON commitment. No original input bytes are embedded in this token or the synthetic review output. For real content, metadata/hashes themselves may be subject to contractual restrictions; never publish restricted data or derivative metadata without authorization.

## Claims deliberately **NOT** supported

A successfully verified token yields `RFC3161_CRYPTO_VALID_UNATTESTED` plus `token_crypto_verified=true`. It deliberately leaves:

- `trusted_time_verified=false`
- `external_attestation_verified=false`
- `pit_certified=false`
- `rights_legally_cleared=false`

The demo CA and TSA are ephemeral and self-issued. The trust anchor is caller-supplied; we do **not** verify real issuer identity, certificate revocation history (CRL/OCSP), archival signing validity, externally witnessed request issuance, or TSA clock integrity. Nor does a token prove that a news item reached a particular authorized user before a decision. The full PIT proof requires independent source-receipt evidence, certified availability semantics, governed latency, historical user rights, and audit provenance.

## Platform and dependencies

- Python 3.10+
- Existing v0.1 through v0.4B modules
- `asn1crypto==1.5.1` (small, pure-Python ASN.1 parser)
- External **OpenSSL CLI**, with `openssl ts` command; 3.x recommended. Python's `cryptography` wheel does **not** provide that CLI. On Windows, ensure `openssl.exe` is on the `PATH`. Some Git for Windows installations include `C:\Program Files\Git\usr\bin\openssl.exe`, but verify it before use. Check with `openssl version` and `openssl ts -help`.

No internet connection or LSEG SDK is required for the test/demo once the dependencies are available. The synthetic fixture script generates a 2-day self-signed CA and timestamp signer inside the OS temporary directory, and removes its private keys once complete. It does not save or publish them.

## Smoke test

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$python = Join-Path $root '.venv\Scripts\python.exe'
$env:PYTHONPATH = Join-Path $root 'src'
& $python -m pip install -r "$root\requirements-rfc3161-v04c.txt"
if ($LASTEXITCODE -ne 0) { throw 'ASN.1 dependency install failed' }
& openssl version
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL CLI required' }
& $python -m unittest discover -s "$root\tests" -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'test failure' }
```

Expected with OpenSSL available: `Ran 129 tests` and `OK`, **without skipped tests**. When OpenSSL is unavailable, the 20 OpenSSL integration tests are skipped, so the full milestone must **not** be declared passed.

### Lab demonstration

```powershell
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$ledger = "F:\Kario_Data\pit_audit_open_source\synthetic_v04c\demo_$stamp.jsonl"
& $python "$root\examples\synthetic\demo_rfc3161_v04c.py" --ledger $ledger
```

This runs 100% offline and uses only synthetic test data. The input ledger must not already exist. Store the JSON stdout in a private synthetic-only review location.

## Fail-closed examples

- Invalid DER, wrong request, wrong nonce, unsupported imprint, policy not allowlisted: `HOLD_TOKEN_SEMANTICS`
- Signature or certificate chain failure: `HOLD_SIGNATURE_OR_CHAIN`
- Missing explicit CA: `HOLD_TRUST_ANCHOR_MISSING`
- Missing OpenSSL: `HOLD_OPENSSL_UNAVAILABLE`
- Time-stamp certainty bound after decision: `HOLD_TOKEN_AFTER_DECISION`
- Ledger tampering, absent evidence, restricted rights, cloud/training uses: `HOLD_*`

## Relevant standards

- RFC 3161: https://www.rfc-editor.org/rfc/rfc3161
- OpenSSL `ts`: https://docs.openssl.org/3.5/man1/openssl-ts/

The v0.4C module is intentionally standalone and **does not modify or auto-promote** v0.4B's Ed25519 signed claims to verified time. No LSEG-specific adapter is included.
