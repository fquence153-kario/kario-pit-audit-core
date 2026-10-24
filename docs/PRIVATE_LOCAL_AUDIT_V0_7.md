# KARIO v0.7 — Local Private Audit Pilot

Status: **experimental, pre-release, not PIT certified**.

## Purpose

Add an intentionally narrow local read-only replay for **operator-declared `OWNED_PRIVATE`** metadata ledgers created with v0.6. The public v0.3 `DecisionReplayer` still refuses those records. No code or SDK from LSEG, Reuters, FactSet, or other market-data vendors is bundled.

## Requirements and restrictions

- Source input and destination ledger must remain on the user's machine, **outside the public source repository**, in a private workspace. A dedicated ledger per data owner is required operationally; true multi-tenant isolation is **not** implemented.
- This pilot rejects any ledger containing `SYNTHETIC_PUBLIC` or `VENDOR_RESTRICTED` entries, even if they are unrelated to the selected document. It treats `OWNED_PRIVATE` as an **operator assertion**, never independently verified ownership, copyright, confidentiality, or vendor licensing rights. Do not relabel LSEG/Reuters/FactSet content as `OWNED_PRIVATE` to bypass restrictions.
- `--acknowledge-private-rights` is a manual confirmation of the operator's asserted right to process locally; it does not grant or prove any right.
- Require a known SHA-256 digest of the exact on-disk ledger before audit. This is a **local pin for accidental changes**, not an independently signed historical anchor. Original v0.2 hash-chaining and monotonic local recorded timestamps remain mandatory.
- Audit output is redacted by default: no content, provider/source IDs, revision IDs, content hashes, ledger hashes, or paths. The underlying Python API has an explicit `LOCAL_FULL` option for local use with **a second acknowledgement**. Never publish those results.
- No network calls, LLM training, cloud processing, or automated export exist in this module. Those restrictions are **software-intent and policy checks**, not environment attestation or a full data-loss-prevention system.
- Local ingest receipts recorded **after** the relevant historical decision cannot certify earlier real-world availability. `pit_certified`, `trusted_time_verified`, and `rights_legally_cleared` remain `false` in every case.
- Only a local single-user filesystem prototype. No API authentication, RBAC, encryption at rest, hardware key management, server hardening, cross-process atomic snapshot, or production-grade data isolation. The operator must secure the storage separately.

## CLI — private local audit, redacted JSON only

Use an existing v0.6 private-only metadata ledger (not a source CSV). Compute the file hash on the local machine:

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$ledger = 'F:\Kario_Data\private_audit\customer_ledger.jsonl'
$sha = (Get-FileHash -LiteralPath $ledger -Algorithm SHA256).Hash.ToLowerInvariant()
$env:PYTHONPATH = Join-Path $root 'src'
& "$root\.venv\Scripts\python.exe" `
   "$root\tools\private_local_audit_v07.py" `
   --ledger $ledger `
   --provider 'YOUR_OWN_PROVIDER_ID' `
   --source-record 'YOUR_SOURCE_RECORD_ID' `
   --decision-at '2026-10-10T00:00:00Z' `
   --expected-ledger-sha256 $sha `
   --acknowledge-private-rights
```

The timestamp above is illustrative. Choose the actual decision time for your own permitted workflow. This CLI never writes to the ledger; the result is a local, redacted status only. A time-gate pass is **not** a historical PIT certification.

## Synthetic demo

`demo_private_audit_v07.py --output-dir DIRECTORY` generates an entirely **fabricated** R1/R2 dataset labeled `OWNED_PRIVATE` for exercising code paths. The fake label does not transform those test records into proof of real ownership. It verifies R1 before R2, R2 after availability, unchanged ledger, public replay denial, wrong hash pin denial, cloud denial, and no certification flags. Demo output directory must not exist and must be outside the repository.

## Future work before enterprise use

Explicit principal/tenant authentication, server-side storage isolation, source-aware permissions derived from actual contracts, encrypted persistence, signed approval records, external trusted time and historical availability validation, threat modeling, external security review, and truly independent rights verification.
