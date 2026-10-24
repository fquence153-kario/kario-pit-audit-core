# KARIO PIT Audit Core v0.4E | Historical CRL Archive Consistency Lab

**Scope:** offline, synthetic-only, vendor-neutral *logical archive consistency* test. **Not** production PKI, legal clearance, real historical TSA trust, or independent PIT certification.

## New components

- `historical_crl_archive_v04e.py`: runs upstream v0.4C token crypto/ledger/rights/decision checks first, then cross-binds a local manifest, TSA certificate, CRL, request, token and ledger entry hash.
- Checks CA root pin, actual CMS signer identity, CRL signature, direct complete CRL scope, certificates at token `genTime`, CRL `[thisUpdate, nextUpdate)` window at decision, and claims that the local operator first observed the CRL no later than decision.
- All successful outputs: `HISTORICAL_CRL_SNAPSHOT_CONSISTENT_UNATTESTED` with `trusted_time_verified=false`, `historical_status_independently_attested=false`, `pit_certified=false`, `rights_legally_cleared=false`.
- Explicitly refuses missing CRL, changed manifest, content misbinding, pre-issuance or after-decision observation, stale/future CRLs, signer listed in CRL, different root, unknown or restricted data, cloud processing and model training.

## Critical limitations

1. `first_observed_at_utc` in the manifest is a **local operator assertion**. Its SHA256 pin may detect later accidental edits but does **not** stop an operator from forging an earlier time or regenerating all inputs.
2. CRL `thisUpdate` and `nextUpdate` indicate an issuer's dates, not when a given customer could obtain the CRL. An archived CRL needs independently verifiable observation/receipt evidence to support claims of historical availability.
3. v0.4C's OpenSSL certificate-chain verification still checks local wall-clock validity; therefore v0.4E is **not** historical PKIX validation of expired certificates and cannot establish historical nonrevocation.
4. This implementation supports only one self-signed pinned synthetic CA, a direct TSA and a complete direct CRL, with no delta/indirect CRL, OCSP, production trust store or automatic network retrieval.
5. This project stores neither raw provider data nor private keys; all synthetic private keys live in temporary lab folders. Only synthetic fixtures are permitted, and external/vendor data is rejected upstream.
6. CRL not listing a TSA certificate does not prove the signer was never revoked outside the supplied CRL interval or that any source content was available to a given market participant.
7. No real TSA contract/certificate, LSEG SDK or integration, external audit attestation, or data resale license is included.

## Installation and execution

Install the patch as *new files only*, never overwrite an existing module. In Windows PowerShell create temporary `openssl.cnf` with `OPENSSL_CONF`, as required for earlier v0.4C tests. Set `PYTHONPATH` to `D:\Kario_PIT_Audit_OpenSource\src`. Run:

```powershell
& $python "$root\tools\run_strict_tests_v04e.py" "$root\tests"
& $python "$root\examples\synthetic\demo_historical_crl_v04e.py" --ledger $ledger
```

Store demonstration output in `F:\Kario_Data\pit_audit_open_source\synthetic_v04e`. Do not upload real data to this repository. Before any public release conduct dependency/license/IP, synthetic-fixture and Git-history reviews.

Standards background: RFC 5280 (CRL profile) and RFC 3161 (time stamp protocol). The v0.4E result is an explicitly untrusted laboratory consistency assessment, not standards-conformant production validation.
