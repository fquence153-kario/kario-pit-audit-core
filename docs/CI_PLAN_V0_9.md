# KARIO CI draft — NOT ENABLED

Do not create a public GitHub repository from this plan. Before installing a workflow into `.github/workflows`, extend the v0.8 public-file allowlist under code review and check Git history for restricted data.

Minimum future CI checks after legal/security approval:

- `pull_request` and limited `push` triggers only; no scheduled publishing, deployment or release job.
- Separate Linux and Windows jobs, Python 3.11 and 3.13 (3.10 smoke is a later compatibility gate), using reviewed pinned dependencies.
- Enforce the exact unittest count and zero skipped tests; temporarily create a minimal `OPENSSL_CONF` for lab fixtures.
- Offline source preflight and wheel-content checks against the candidate files; a local wheel may be created, but **do not upload artifacts** by default.
- No `secrets:` references, OAuth tokens, LSEG SDKs, licensed datasets, external market-data calls, model training or customer data.
- Maintain `public_release_authorized=false` in all automatic machine reports until independent review and explicit human signoff.

This document is a checklist, not executable CI. The absence of a workflow is intentional while v0.8 release policy and legal ownership review are unfinished.
