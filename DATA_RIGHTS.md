# Data Rights and Distribution Policy (pre-release)

This policy distinguishes **software-license rights** from **data rights**.
The project's Apache-2.0 `LICENSE`, subject to contributor ownership review,
does not license any market-data, news, customer, or third-party content.

## What may be in a public source release

- Original, reviewed software and documentation that the maintainers have
  the right to redistribute.
- Clearly marked synthetic test fixtures created for this project, with no
  real client, exchange, or licensed vendor content embedded in them.
- Approved dependency notices, reproducible hashes and non-sensitive metadata.

## What must remain out of the public repository and Wheel

- LSEG / Reuters content, transcripts, records, SDKs or other vendor-restricted
  data and any derived output whose redistribution is not expressly licensed.
- Client `OWNED_PRIVATE` documents, ledgers, identifiers, hashes, reports,
  evaluation artifacts or raw records. Even hashes can reveal information.
- Live API credentials, tokens, certificate private keys, private test material
  and other secrets. Synthetic key fixtures need independent release review.

## Runtime rights classes and trust gates

- `SYNTHETIC_PUBLIC`: local synthetic examples only; verify content is actually
  synthetic before considering public distribution.
- `OWNED_PRIVATE`: local processing may be enabled only after explicit operator
  acknowledgment. This is an assertion, **not** legal clearance. No automatic
  public export, model training, vendor redistribution or cloud transmission.
  The separately gated private audit outputs are intended to be redacted.
- `VENDOR_RESTRICTED`: fail closed in open-core intake and demonstrations.
  Any vendor connector requires its own written usage, retention and
  redistribution authorization and a separate deployment/review path.

A successful timestamp comparison, local hash-chain check, signature
verification, or operator acknowledgment cannot establish licensed usage,
independently trusted historical time, or certified PIT availability.

## Release procedure

Keep production and research data outside the repository. Review every
allowlisted file, dependencies and transitive licenses, test fixtures, the
Git index and any earlier code provenance. Do not publish a Wheel, repository,
report or source-data derivative merely because automated checks show zero
blockers. Approval is a separate documented manual decision.
