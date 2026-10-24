# KARIO PIT Audit Core v0.5 — Synthetic Feedback Flywheel Lab

**Scope:** append-only synthetic audit feedback, independent case adjudication, proposed policy version, actual baseline regression and candidate freeze for review. This is a **governance prototype**, not an AI training workflow or production feedback optimizer.

## Sequence

1. `CASE_OPENED`: bind an explicit issue code, decision timestamp, entry hash and immutable original PIT audit status from the **verified v0.2 EvidenceLedger**.
2. `CASE_ADJUDICATED`: a different reviewer sets `CONFIRMED`, `REJECTED` or `NEEDS_MORE_EVIDENCE`. No changes to source evidence or PIT status.
3. `RULE_PROPOSED`: only a `CONFIRMED` case can nominate a **new, unimplemented** policy version and matching change category.
4. `BASELINE_REGRESSION`: run 6 built-in deterministic **existing v0.1 baseline** scenarios. Passing does NOT mean the candidate is implemented or tested.
5. `CANDIDATE_FROZEN`: a fourth, independent approver may freeze a proposal **for further review only**. The system has no promotion/install path.

The source ledger is always read-only to the feedback module; a separate JSONL journal with local hash chaining records feedback events. On reads and writes, source evidence references and their baseline audit status are checked again. Event hashes are not externally anchored; journal entries can be rewritten and rehashed by a privileged attacker.

## Boundaries

- **Never import or use real LSEG, Reuters, FactSet, student Workspace, other third-party, or customer datasets in public feedback.** Real records, hashes, metadata and business case details may themselves be restricted.
- Only `SYNTHETIC_PUBLIC` evidence is allowed in this lab, with enumerated issue/change codes and pseudonymous IDs. No article content, free text, API tokens, private keys, vendor IDs or embedding exports.
- A human verdict is not an independent signed or timestamped provenance proof. Local recorded timestamps are not trusted time.
- No PIT certification, no legal clearance, no production policy change, no model fitting, and no training example export.
- The 6 regressions check old logic only. Candidate performance/regressions and independent approval are a separate future stage.
- One process writer at a time; max journal 16 MiB. Not a production database or transactional multi-process service. Do not share writable journals across network filesystems.
- Do not publish the F: demonstration journals, even when synthetic, without a separate release content/security inspection.

## Usage

With the user's existing virtual environment and v0.4E prerequisites:

```powershell
$root = "D:\Kario_PIT_Audit_OpenSource"
$env:PYTHONPATH = "$root\src"
& "$root\.venv\Scripts\python.exe" "$root\tools\run_strict_tests_v05.py" "$root\tests"
```

The demo takes two **new** paths:

```powershell
& "$root\.venv\Scripts\python.exe" "$root\examples\synthetic\demo_feedback_flywheel_v05.py" `
    --ledger "F:\Kario_Data\pit_audit_open_source\synthetic_v05\demo_unique.jsonl" `
    --feedback "F:\Kario_Data\pit_audit_open_source\synthetic_v05\feedback_unique.jsonl"
```

Expected fixed run count: see `tools/run_strict_tests_v05.py`. Preserve the existing historical CRL test dependencies (OpenSSL CLI and `OPENSSL_CONF` on Windows).
