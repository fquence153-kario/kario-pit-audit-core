# KARIO v0.4 — Source and rights governance preflight

## Status
PRE-RELEASE, additive pilot. NOT a trustworthy external timestamp authority.
No API or LSEG dependencies. No changes to v0.1/v0.2/v0.3.

## Scope
- Consumes verified v0.3 historical replay result (read-only).
- Supports only explicitly allowlisted synthetic fixture IDs for `LOCAL_SYNTHETIC_TEST` and `PUBLIC_SYNTHETIC_DEMO`.
- Any source class other than `SYNTHETIC_PUBLIC` remains denied by v0.3; v0.4 has no vendor-data bypass.
- Local operator source assertions are validated for shape, linked record/hash, timezone and assertion not later than decision. They are explicitly UNTRUSTED, UNSIGNED declarations.
- Data with missing or corrupt ledgers, invalid rights, late versions, unrecognized proof claims, or invalid decisions fails closed.
- `pit_certified`, `independent_provenance_verified`, `external_attestation_verified`, `rights_legally_cleared` always remain `false`.

## Do not misconstrue output
`synthetic_demo_policy_pass=true` is a test-harness decision, NOT any legal authorization, independently verified timestamp, or approval to re-distribute real datasets. Hash-chain integrity is not authenticity; local clock is not a trusted external authority.

## Next: v0.4B/v0.5 needs
- An externally trusted timestamp receipt and *cryptographic verification* against an explicitly reviewed issuer/trust store, with certificate/key rotation and revocation policies.
- A customer-controlled rights entitlement registry with product, field, usage, retention, destination, and contract-scoped permitted purposes and default-deny policy. Legal review needed per provider; not self-certification.
- Merkle/log anchoring or other tamper-evident checkpoints stored independently of the local ledger, plus clock integrity, asynchronous correctness and stress/security tests.
- Clear proof-of-availability semantics: a valid signature on a late receipt does not prove early user availability.

## Vendor independence
LSEG/FNSPID/Reuters payloads, proprietary identifiers, credentials and derivatives must never be added to this repository or to synthetic test examples.
