# KARIO PIT Audit Core v0.2 — Evidence Registry Pilot

## Scope

This is a **vendor-neutral, dependency-free pilot**. It adds a metadata-only JSONL
ledger to the pre-existing `kario_pit.audit.time_gate` v0.1 module.

- `EvidenceLedger.append(...)` computes SHA-256 from in-memory bytes; it **never**
  persists those bytes, only the digest and minimal metadata.
- `observed_at_utc` and `availability_upper_at_utc` are both derived from the
  local machine's clock at append time. Inputs cannot claim an earlier historical
  capture time.
- A numbered, SHA-256-linked JSONL ledger permits local consistency checks.
- Revision IDs are unique per source document; later revisions must explicitly
  supersede the previous latest version.
- `audit(evidence_id, decision_at)` invokes the existing v0.1 time gate. All
  successful time comparisons remain `TIME_GATE_PASS_UNVERIFIED`, with
  `pit_certified=false`.
- `rights_class` is an **operator-declared tag**, NOT independent permission
  verification. No user, vendor or third-party metadata should be published
  merely because it was accepted by this registry.

## Crucial limitations

1. **Not a historical PIT proof.** The local receipt is not externally
   timestamp-attested, and the machine clock may be inaccurate or manipulated.
2. **Not a security-grade immutable log.** A malicious actor can rewrite the
   entire chain and recompute hashes. Independent checkpoint signing/anchoring,
   role-based access and audit storage are future work.
3. **Not full content verification on read.** Because source bytes are not
   retained, an external, authorized copy is required to re-check content hash.
4. **Single-writer JSONL pilot only.** The lock file avoids routine concurrent
   appends; there is no distributed lock, transaction database or large-volume
   storage. Do not point this tool at legacy KARIO/LSEG data or 30GB archives.
5. **No automatic rights clearance.** A digest, source ID, derived result, or
   timestamp from a restricted source may itself be restricted by contract.
6. **No public release approval.** Security, license, source and dependency
   audit must precede GitHub publication.

## Directory/layout

- Code: `D:\Kario_PIT_Audit_OpenSource\src\kario_pit\registry`
- Synthetic demo output (suggested): `F:\Kario_Data\pit_audit_open_source\synthetic_v02`
- Tests: `D:\Kario_PIT_Audit_OpenSource\tests`

## Verify and test (PowerShell)

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$env:PYTHONPATH = Join-Path $root 'src'
& "$root\.venv\Scripts\python.exe" -m unittest discover -s "$root\tests" -p 'test_*.py' -v
```

## Synthetic-only demonstration (PowerShell)

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$env:PYTHONPATH = Join-Path $root 'src'
$ledger = 'F:\Kario_Data\pit_audit_open_source\synthetic_v02\demo_registry.jsonl'
& "$root\.venv\Scripts\python.exe" "$root\examples\synthetic\demo_registry_v02.py" --ledger $ledger
```

The demo **refuses to overwrite** an existing ledger. Choose a new filename to repeat.

## Suggested v0.3 work

Evidence provenance classification; strict proof types; external timestamp
anchors; authorized hash re-verification; decision snapshot replay; privacy and
rights-aware export rules; independent source-time validation.
