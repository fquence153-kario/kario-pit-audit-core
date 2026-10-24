# KARIO PIT Audit Core

**Status: PRE-RELEASE — research prototype, not independently PIT-certified.**

KARIO PIT Audit Core is a vendor-neutral, local-first, evidence-oriented
Point-in-Time (PIT) auditing research prototype. It checks whether an
evidence version could satisfy configured decision-time constraints and
records why uncertain cases remain on HOLD.

## Capabilities

- Time gate: compare `availability_upper_at + registered_latency` with the
  decision timestamp, without turning a passing comparison into PIT certification.
- Local evidence-hash registry, append-only-style ledger integrity checks and
  revision-aware historical replay.
- Offline signed-receipt / RFC 3161 / CRL experiments using synthetic fixtures.
  Lab signatures or operator-provided timestamps are **not** independently
  trusted historical time.
- Structured feedback governance, bounded local CSV/JSONL intake and a
  separately gated, redacted local audit path for self-declared private data.

## Install and inspect

Use an isolated Python environment. For the initial source-only release,
install from the checked-out repository; Python dependencies are resolved
from their upstream package distributors. For example:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\kario-pit.exe version
```

Installation from source resolves the required Python dependencies. A
separately installed, supported OpenSSL CLI is required for selected RFC 3161
/ CRL workflows and is not bundled with this repository.

## Synthetic time-gate example

```powershell
kario-pit time-gate `
  --decision-at "2026-01-02T10:00:35Z" `
  --availability-upper-at "2026-01-02T10:00:05Z" `
  --registered-latency-seconds 30 `
  --source-published-at "2026-01-02T10:00:00Z"
```

`TIME_GATE_PASS_UNVERIFIED` means the supplied timestamps satisfy the
comparison; it does **not** prove that historical data was independently
available, that the source is authentic, or that the content may be reused.
Missing or contradictory evidence must remain on HOLD. For the other commands,
run `kario-pit --help` and read the documents under `docs/`.

## Security, privacy and legal boundaries

Do not import proprietary vendor data into public examples or upload a client's
private ledger to a repository. `OWNED_PRIVATE` audit features require explicit
local-use acknowledgment; that acknowledgment is not legal authorization.
Identifiers and hashes may themselves be sensitive; keep local outputs outside
the public source tree. This project does not connect to LSEG / Reuters services
or include licensed vendor datasets, credentials, or commercial connectors.

Read [DATA_RIGHTS.md](DATA_RIGHTS.md) and [LICENSE](LICENSE). Apache-2.0
covers only code for which the copyright holder has authority to grant it; it
never licenses third-party financial data. See `docs/TIME_GATE_HARDENING_V09C.md`
for the conservative input-validation changes to the original v0.1 time gate.

**No production-grade PIT certification, independent trusted-time attestation,
customer-data legal clearance, or vendor-data redistribution rights are claimed.**
