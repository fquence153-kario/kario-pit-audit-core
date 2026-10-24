# v0.9C — v0.1 Time Gate Input Hardening (pre-release)

This is a small **input-safety patch** to the legacy `KARIO_TIME_GATE_V0.1`
calculation. It deliberately preserves the existing `policy_version`, time
comparison formula, inclusive decision boundary and the `pit_certified=False`
behavior for valid inputs. It does **not** back-certify historical observations.

Changes:

1. A provided-but-empty/invalid `source_published_at` is now rejected instead
   of being silently treated as absent; only `None` means not supplied.
2. An omitted `availability_upper_at` (`None`) returns the existing
   `HOLD_MISSING_AVAILABILITY`; a malformed value such as `""` now returns
   `HOLD_INVALID_INPUT`.
3. Evidence IDs must match the registry's conservative `[A-Za-z0-9._:-]`
   1–128 character contract; an invalid ID is not echoed in the response.
4. Raw exception text is never returned. The existing `diagnostic` field on
   invalid inputs uses the fixed code `INVALID_TIME_GATE_INPUT`.
5. `TIME_GATE_PASS_UNVERIFIED` still denotes only local calculation, not
   trusted time, legal data rights or PIT certification.

These are deliberate tightening changes for invalid inputs. Do not treat this
as proof of equivalence on every possible malformed legacy input. The patch
is targeted at the frozen 81-file v0.9B candidate snapshot and will refuse
to change files whose hash or reviewed baseline differs.

The installer archives the three original bytes on F: and emits before/after
hashes. As soon as installation succeeds, the v0.9B candidate SHA manifest is
**historical** and must be re-scanned into a new candidate manifest. Do not
change `public_release_authorized=false` or `code_origin_review=PENDING`.

The new standalone safety tests live in
`tools/selftest_time_gate_hardening_v09c.py`, outside `tests/`, so the
previously frozen v0.9 strict runner still checks exactly 408 tests. Execute
both suites separately; neither alone is a production-release gate.

The existing v0.9 Wheel must be rebuilt with a new artifact checksum after
this source change. Its wheel filename and dev version may remain unchanged,
so avoid confusing the old and new Wheels; use distinct build directories.
The patch does not modify the old historical evidence ledger or any private
client datasets.
