# KARIO PIT Audit Core v0.3 — Decision Snapshot Replay (Synthetic Pilot)

## Purpose

Deterministically select the **latest revision that was usable at T**, rather
than accidentally returning the latest revision now. This is a small, offline,
read-only replay layer on top of the v0.2 metadata-only `EvidenceLedger`.

## API

```python
from kario_pit.replay import DecisionReplayer

replayer = DecisionReplayer("/path/to/local/synthetic-ledger.jsonl")
result = replayer.replay_document(
    provider_id="MOCK",
    source_record_id="SYN-REPLAY-DOC",
    decision_at="2026-01-02T10:00:30Z",
)
```

The public pilot only selects records labelled `SYNTHETIC_PUBLIC`, where those
labels are operator-declared, **not externally verified rights clearance**.
In this version, do **not** put any vendor/customer/real-user data into the
replay demo or public Git repository. A separate, contract-aware private policy
and permission model will be required for non-synthetic evidence.

## Selection rules

1. **Fail closed** if the v0.2 registry hash-chain/record structure fails
   verification, or the recorded local receipt timestamps move backwards.
2. Filter by exact `provider_id` and `source_record_id` (no fallback searches).
3. Consider only revisions observed by T. No future revision metadata, count,
   or latest ledger head hash is exported in successful snapshot results.
4. Check declared rights class; refuse any non-`SYNTHETIC_PUBLIC` version
   observed by T (conservative output policy for this public pilot).
5. Require source-published timestamps and non-conflicting chronology.
6. A revision is eligible only if `availability_upper_at_utc +
   registered_latency_seconds <= decision_at`, using v0.1 `audit_time_gate`.
7. Choose the latest eligible revision in the v0.2 linear append/revision order.
   A newly observed revision does **not** replace an earlier usable revision
   until the new revision itself becomes usable at T.
8. Return `TIME_GATE_PASS_UNVERIFIED` with `pit_certified=false` on selection.
   A pass is **not** independently verified historical availability.

## Why this is not certified historical PIT

- The v0.2 ledger timestamps use the **local machine clock** when written, and
  this clock has no external, trusted historical attestation. A forged/incorrect
  clock can backdate evidence without being detected by an unanchored hash-chain.
- The ledger's SHA-256 chain detects *uncorrected* changes, but an actor can
  rebuild the chain and recompute hashes. This is not an authenticated ledger.
- Source published times and `SYNTHETIC_PUBLIC` rights labels are unverified
  operator assertions. No legal permission is conferred by accepting them.
- v0.3 does not store the original bytes and cannot revalidate content hashes
  without a separate authorized source copy.
- All revisions and metadata in the present-day file are verified for local
  integrity. If a later revision corrupts the ledger, even an earlier replay may
  return HOLD. This fail-closed behavior is deliberate and is NOT as-of data.
- The output is an *index* selecting a revision; it is not the financial event
  feature itself, and does not support model alpha claims.
- This v0.3 layer uses the read-only internal method
  `EvidenceLedger._verify_and_load()` pinned to the v0.2 pilot. Later versions
  should expose a stable verified-entries API and add independent time anchors.

## No-vendor independence

Standard-library Python only. No API keys, LSEG SDK, live data adapter, network
requests or price/news records. Keep code on `D:` and generated demo artifacts
on `F:`. Do not copy or reference the original private KARIO data directories.

## Tests and Windows demo

```powershell
$root = 'D:\Kario_PIT_Audit_OpenSource'
$env:PYTHONPATH = Join-Path $root 'src'
$python = Join-Path $root '.venv\Scripts\python.exe'
& $python -m unittest discover -s (Join-Path $root 'tests') -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$ledger = "F:\Kario_Data\pit_audit_open_source\synthetic_v03\demo_$stamp.jsonl"
& $python (Join-Path $root 'examples\synthetic\demo_replay_v03.py') --ledger $ledger
if ($LASTEXITCODE -ne 0) { throw 'Demo failed' }
```

Expected test count: 44 (6 v0.1 + 18 v0.2 + 20 v0.3).

## Suggested v0.4

Independent timestamp attestation/anchors, read-only stable registry interface,
content re-verification from authorized local storage, private-user rights gate,
export deny-by-default, and CI/licensing/security release checks.
