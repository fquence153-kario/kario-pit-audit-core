# KARIO PIT Audit v0.4B — Synthetic Signed Receipt Laboratory

**Status: laboratory implementation only; cannot certify historical PIT.**

## Objective

Use Ed25519 to test cryptographic binding between a signed *claim* and the verified metadata-only Evidence Ledger v0.2 plus the chosen as-of revision from Decision Replay v0.3. Governance Preflight v0.4 still blocks non-synthetic and forbidden uses.

## Bound fields

Each detached lab signature covers a canonical, domain-separated JSON message containing: evidence ID, revision ID, ledger entry hash, content SHA-256, provider and source IDs, decision time, effective local availability time, self-declared signer time, proof kind, signer key ID and schema version. Unknown fields, missing fields and malformed timestamps are rejected.

## What it actually verifies

- Signature checks against a *caller-provisioned* Ed25519 lab public key; the receipt cannot supply its own trust anchor.
- Fail closed on unknown/revoked/out-of-window lab keys; the lab trust store is a static local test fixture.
- Fail closed on evidence/revision/content/entry/decision/source mismatch and on future self-declared signing-time claims.
- Fail closed on missing/broken ledger and on v0.4 governance rejection.
- No private key is written to disk by the demo; an ephemeral private key is generated only in memory.

## What it does NOT prove

- The `claimed_signed_at_utc` field is authenticated as a field **inside the message**, NOT independently time-stamped; a key owner could sign a backdated claim later.
- A valid signature alone does not prove what information a historical user could see, timely receipt, reliable clock, legally permitted use, or correctness of content.
- This module does **not** implement RFC 3161 Time Stamp Tokens, a Time Stamp Authority, external trust root, certificate chain, CRL/OCSP, historical revocation validation, independently hosted immutable audit anchors, or a PIT-certification policy.
- `signature_valid` may be true. `trusted_time_verified`, `external_attestation_verified`, `independent_provenance_verified`, `rights_legally_cleared` and `pit_certified` **always remain false**.
- It does not authorize LSEG / Reuters / any vendor content, cloud processing, or model training.

## Requirements

Python >=3.10; optional isolated environment dependency: `cryptography==46.0.4`. The existing v0.1-0.4 code remains unmodified, including every older unit test. If the crypto package is unavailable, verifier returns `HOLD_CRYPTO_UNAVAILABLE` rather than accepting unsigned results.

## Integration and next phase

A production-grade trusted time verifier requires verified, externally obtained evidence such as RFC 3161 TST with signature, nonce or message-imprint matching, acceptable policy OIDs, qualified anchor list, status and certificate-chain validation, and historical revocation evidence. Even that alone proves existence of a *hash* at some time—not that the source was made available to the relevant decision maker. Plan v0.4C as a separately reviewed implementation. Vendor adapter remains separately licensed and out of tree.

## Security / release controls

Synthetic fixtures only. Never commit provider data or real cryptographic keys. Keep the persistent ledger on the F: data disk and Python code on D:. Before any public release, undertake third-party source-code/security review, dependencies/SBOM licensing assessment and negative testing against hostile inputs.
