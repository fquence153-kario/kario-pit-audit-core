# KARIO PIT Audit Core v0.4D — Offline CRL policy lab

**PRE-RELEASE, synthetic fixtures only. No production trust, historical
non-revocation, independent timestamping or PIT certification.**

This is an additive, read-only gate on top of v0.4C RFC 3161 token validation.
It checks:

- a SHA-256-pinned synthetic CA root already used by the v0.4C verifier;
- directly issued TSA signing certificate & CA key-usage profiles;
- a complete, direct, issuer-matched CA-signed CRL;
- CRL signer signature, AKI/SKI binding, CRL number and scope;
- `thisUpdate <= local verification clock <= nextUpdate`;
- whether the supplied CRL lists the TSA certificate serial number.

Successful local result is `CRL_NOT_LISTED_UNATTESTED`. This means only that
**one locally supplied and cryptographically validated CRL** does not include
this TSA serial number, and was within its declared time interval according to
an untrusted local system clock. It is NOT a trusted OCSP/CRL status for a
past date, nor proof that the signer was never revoked or that its signing
operation occurred when claimed. Do not label this result `GOOD` or `PIT_CERTIFIED`.

The module does not download CRLs or perform OCSP, check archival validation,
validate independent issuer accreditation, persist signed policy snapshots,
handle delta/indirect/restricted-scope CRLs, prove a trusted system clock,
anchor a genuine historical proof-of-existence, or authenticate data user access.
All such cases remain unimplemented; production use must fail closed.

No LSEG/Reuters data, adapter, SDK, credential, source bytes or real vendor
permission is bundled. Any actual vendor usage needs contractual clearance.

## Dependencies

Existing v0.1–v0.4C package. Python `cryptography==46.0.4`, installed by
v0.4B. OpenSSL CLI required by v0.4C. No further Python dependencies.
Windows users should retain the v0.4C Windows OpenSSL path hotfix and provide
an appropriate temporary `OPENSSL_CONF` for test certificate generation.

## Run synthetic tests

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$python = Join-Path $root '.venv\Scripts\python.exe'
$env:PYTHONPATH = Join-Path $root 'src'
& $python -m unittest discover -s "$root\tests" -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'test failed' }
```

Do not count `skipped` tests as passing OpenSSL/TSA integration acceptance.

## Standards

- RFC 5280: https://www.rfc-editor.org/rfc/rfc5280
- RFC 3161: https://www.rfc-editor.org/rfc/rfc3161
- OpenSSL `verify` CRL options: https://docs.openssl.org/3.5/man1/openssl-verify/

New outputs always preserve `trusted_time_verified=false`,
`external_attestation_verified=false`, `pit_certified=false`,
`rights_legally_cleared=false`. The v0.4C verifier remains unchanged.
