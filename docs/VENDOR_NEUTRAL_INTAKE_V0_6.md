# KARIO PIT Audit Core v0.6 — Vendor-neutral local CSV/JSONL intake

**Status:** pilot for local ingestion and schema normalization. **Not a data license verifier, public publishing permission, independent trusted timestamp, or historical PIT certificate.**

## Input contract

Exactly nine fields in UTF-8 `.csv` (single header) or `.jsonl` (one object per line). Unrecognized/duplicate fields rejected. Max **2 MiB file**, **100 records/batch**, **256 KiB text/record**, **7 days registered latency**. For CSV leave a missing `supersedes_evidence_id` as an empty cell; for JSONL use `null`. All times must be timezone-aware ISO 8601, and source publication timestamps must not be in the future relative to ingestion.

| Field | Type | Description |
|---|---|---|
| evidence_id | string | Unique immutable record ID, `[A-Za-z0-9._:-]{1,128}` |
| provider_id | string | Source identifier (synthetic mode must be `SYNTHETIC`) |
| source_record_id | string | Document/source key |
| revision_id | string | Revision label (R1/R2, etc.) |
| supersedes_evidence_id | string/null | Must point to the latest recorded revision of that document |
| source_published_at | timestamp | Source-provided claim, not independent time evidence |
| registered_latency_seconds | integer | Explicit, nonnegative registered policy (0..604800) |
| rights_class | enum | `SYNTHETIC_PUBLIC` or `OWNED_PRIVATE` in this pilot |
| content_text | UTF-8 text | Raw input content for local hashing, **not copied to destination ledger** |

## Supported modes

- `LOCAL_SYNTHETIC` is the **default**. Requires `SYNTHETIC_PUBLIC`, provider_id `SYNTHETIC`, and evidence_id prefix `SYN-`. Those labels do **not** independently prove the content is synthetic or licensed for release. Do not use for vendor source records.
- `LOCAL_OWNED_PRIVATE` is for **operator-owned, locally processed data only**, requires an explicit `--acknowledge-private-rights` CLI flag. This is only an assertion by the operator; it does not prove actual ownership, license sufficiency, or LSEG permissions. The private input and derived ledger should remain on a controlled, non-public local volume.
- **No** `VENDOR_RESTRICTED` import in v0.6. LSEG, Reuters, FactSet, and other licensed provider data are **not** converted into public-safe material merely by passing through a local parser or hashing it. Consult vendor agreements and, for LSEG, an independently licensed commercial adapter.

## Commands (Windows)

With the project's `PYTHONPATH` set to `D:\Kario_PIT_Audit_OpenSource\src`:

```powershell
& $python "D:\Kario_PIT_Audit_OpenSource\tools\import_local_v06.py" `
  --input "F:\Kario_Data\pit_audit_open_source\synthetic_v06\sample.csv" `
  --ledger "F:\Kario_Data\pit_audit_open_source\synthetic_v06\local.jsonl"
```

The default command is **read-only dry run**. Add `--apply` to commit a verified metadata-only batch. To import **genuinely owned** private data, select `--mode LOCAL_OWNED_PRIVATE --acknowledge-private-rights`, without uploading or sharing either source or ledger. Any import mode should be used only with materials the operator actually has permission to process.

## Storage and audit semantics

- Validates all rows and revision linkage before any write. Upon `--apply`, acquires the legacy v0.2 ledger lock, re-verifies the existing ledger, stages all appends to a separate local JSONL file in the same directory, then commits with `os.replace`. In ordinary single-writer local filesystem usage an invalid later row cannot partially commit. This is **not** a multi-host transaction manager; crash durability, network shares, fsync of directory entries and external append writers need separate production hardening.
- The destination ledger stores **content SHA-256, IDs, source publication claim, local receipt time, rights label and revision**. It **does not store raw `content_text`**. The original source file remains at its input path; this importer does not delete it. Hashes, IDs and metadata themselves may be license-restricted or sensitive.
- The underlying v0.2 ledger records its **local ingestion time** rather than claiming original historical receipt time. Backfilled data **cannot** gain a historical availability certificate by import.
- For an owned-private ledger, existing v0.3 public replay returns `HOLD_RIGHTS_POLICY`. v0.6 does **not** change that restriction. A later private-safe auditing API must be designed and tested independently.
- Output flags `trusted_time_verified`, `rights_legally_cleared`, `pit_certified` and `private_data_public_export_authorized` are always `false`. Valid local ingestion is not legal permission, trusted timestamp or a predictive feature.
- No cloud requests, no network dependencies, no LSEG SDK, and no change to the previous audited modules.

## Next hardening milestones

Explicit local rights-policy profiles, private-safe no-export as-of audit interface, cross-platform packaging, user data threat model, artifact lineage, recoverable batch receipts, multi-process reliability, fuzz tests, documentation and independent third-party security/license review before any public release.
