# KARIO PIT Audit Core v0.8 — Offline Release Preflight

**Status: experimental, PRE-RELEASE. Nothing is published or legally authorized.**

This release preflight is an additional local **source-tree inspection tool**, not a security certificate, independent legal opinion, software composition analysis (SCA), or GitHub release workflow. It does not package the repository, contact GitHub, run network calls, call LSEG, export raw data, or modify existing PIT audit verdicts. It never sets `public_release_authorized=true`.

## Main risk model

- **Public code**: `src/kario_pit/**/*.py`, root build metadata, selected `tools/*.py`, `tests/test_*.py`, `examples/synthetic/*.py`, `docs/*.md`, root README/DATA_RIGHTS/LICENSE/requirements. This is a *candidate review manifest*, not the complete rights-cleared list.
- **Outside the manifest**: local data CSV, JSONL, generated ledgers, review reports, logs, archives, real credentials, private customer records, cryptographic private keys and unknown files. These are not proposed for release. Unknown files in the repository are treated as blockers, even if `.gitignore` would normally hide them.
- `.venv` / `.git` and Python caches are excluded. This scan **does not inspect their contents or Git history**. If Git exists, currently tracked files are reviewed against the same narrow allowlist; this does not rule out previously committed secrets. Manually inspect the full history and rotate all exposed credentials before publication.
- Prohibited direct imports from named financial-data-vendor SDKs are flagged. Mentioning LSEG licensing as policy documentation is allowed. Vendor-compatible or proprietary code ownership must still undergo separate human review.
- A few common secret patterns are inspected in text files. This cannot detect all credentials or subtle personal/private data in innocuous metadata. Human review and a trusted independent secret scanner remain necessary.
- The preflight recognizes manually provided `LICENSE` and `pyproject.toml`, but **does not create them**. A placeholder license is not a valid legal grant. Each dependency's license remains `PENDING_MANUAL` regardless of metadata inventory.

## Why the scan is not permission to publish

`status=MANUAL_REVIEW_ONLY` means **zero mechanical blockers from this limited scan**. It never means rights clearance, trusted timestamp, PIT certification, completed external review or public release approval. `status=BLOCKED` means at least one mechanical blocker exists; review the generated file and remediate manually. The `--require-clean` switch returns nonzero for blockers, but still does not confer release permission.

## Windows PowerShell example

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$python = Join-Path $root '.venv\Scripts\python.exe'
$report = 'F:\Kario_Data\pit_audit_open_source\preflight_v08\preflight_report.json'
& $python "$root\tools\release_preflight_v08.py" --root $root --report $report
if ($LASTEXITCODE -ne 0) { throw 'Release preflight could not finish' }
```

The report is written **outside the repository**. It contains only metadata and hashes of candidate source files (not raw source code), but should nevertheless be treated as a local-only review document. The CLI is a dry inspection by default and has no publish switch.

## Outstanding work before GitHub publication

1. Freeze and verify actual public code copyright and contributor provenance; select `LICENSE` only after ownership review.
2. Audit third-party Python packages and licenses, their transitive dependencies, and how OpenSSL binaries will be installed and distributed; pin reproducible versions and check vulnerabilities.
3. Review `.gitignore`, all Git-tracked files and complete Git history (this tool does not inspect historical commits); review any source maps, README, example outputs and release automation.
4. Recreate a clean, separate public working tree from explicitly approved files and perform independent secret scanning, static analysis, package installation tests and no-vendor smoke tests.
5. No LSEG/Reuters/FactSet licensed content, client-private datasets, original private evidence, signed customer attestations or vendor-only adapters in the public repository.
6. Add actual maintainer-approved documentation for security disclosures, provenance, contributor policy and CI/CD release approvals; do not publish until authorized.

The v0.7 `OWNED_PRIVATE` path is a local operator assertion, not verified ownership or commercial permission; this preflight never changes it. The v0.1–v0.7 PIT proofs remain experimental and no historical PIT certification is granted.
