# KARIO PIT Audit Core v0.9 — offline packaging validation (PRE-RELEASE)

**Scope:** Local, vendor-neutral Python distribution, restricted command line, and offline source-whitelist build. The results are neither PIT certification nor legal clearance. No Git push, package registry upload, vendor SDK, cloud transfer or auto-release is included.

## Deployment boundaries

- v0.8A Apache-2.0 declaration represents operator self-confirmation only; independent code ownership and third-party licenses remain for manual review.
- The build process copies only the mandatory root metadata and `src/kario_pit/**/*.py` from the v0.8 candidate manifest into a temporary location OUTSIDE the repository.
- The packaging metadata changes `0.8.0.dev0` to `0.9.0.dev0` and registers `kario-pit = kario_pit.cli_v09:main`, with a verified local backup created first. The tool defaults to preview; `--apply` is an intentional write.
- `python -m kario_pit` also works from an installed distribution (or the source tree with `PYTHONPATH=src`).
- The local wheel content scanner accepts only package Python modules and required wheel metadata; rejects CSV, JSONL, credentials, extra data, unexpected imports, and packaging anomalies. This is not a complete code-security review.
- Build dependencies must ALREADY be installed in the project's dedicated venv (`setuptools` + `wheel`). Build does not install or download anything; failure stops the flow. CRL/RFC3161 test paths still require OpenSSL when running the full regression.
- A `--no-deps` isolated install smoke test validates CLI wiring, not a complete dependency resolution test. Full installation must be separately tested with reviewed pinned Python wheels on Windows/Linux.

## CLI (all outputs are UNATTESTED)

```powershell
kario-pit version
kario-pit time-gate --decision-at 2026-01-01T00:00:10Z --availability-upper-at 2026-01-01T00:00:05Z --registered-latency-seconds 5
kario-pit intake --input C:\path\synthetic.csv --ledger F:\Kario_Data\synthetic_ledgers\ledger.jsonl
# Append only when reviewed and explicitly requested:
kario-pit intake --input C:\path\synthetic.csv --ledger F:\Kario_Data\synthetic_ledgers\ledger.jsonl --apply
```

Private-only routes require `--acknowledge-private-rights` (a declaration, not legal authorization), a local private ledger, and a SHA-256 pin for audit. The public replay interface remains unchanged and does not authorize private data. CLI refuses data transfer and always leaves `pit_certified=false`.

## Windows operating procedure

1. Verify the incremental patch ZIP SHA-256, install only its explicit files with no overwrite. Do **not** paste third-party restricted data into the source tree.
2. Run `tools/prepare_pyproject_v09.py --root <repo> --archive <F drive archive>` in preview mode; verify that it plans only a version and console entry update. Re-run with `--apply` after inspecting its output. It refuses unexpected metadata and archives the previous version.
3. Run v0.9 strict tests with the same OpenSSL temporary configuration used in v0.8. Zero skips, exactly the expected number of tests.
4. Run `tools/build_wheel_v09.py --root <repo> --output-dir <F drive release_internal path>`. The output wheel is a **local candidate**, not authorized for publishing.
5. Optionally run `tools/check_wheel_v09.py --wheel <wheel>` and a clean `venv` with `pip install --no-index --no-deps <wheel>`; verify `kario-pit version` and the synthetic `time-gate` command.
6. Re-run the v0.8 release preflight on the source tree and keep `public_release_authorized=false`. Review `MANUAL` flags, dependency licenses, Git index/history, residual source provenance, LSEG/data restrictions.

### Known blockers to public v1.0

- No independent third-party code ownership and dependency-license audit.
- No verified real historical timestamps or independent source-availability attestations.
- No real enterprise security assessment, tenancy isolation, encrypted private storage, or data-rights enforcement outside synthetic mock policies.
- No assessed Git commit history or external reproducible Windows/Linux build matrix.
- No LSEG paid connector or commercial developer/data rights license.

## CI policy

A proposed GitHub Actions CI workflow is documented in `docs/CI_PLAN_V0_9.md` only; **no** `.github/workflows` is installed in this patch because the v0.8 allowlist would correctly block unapproved workflow files. CI must never include data, secret or artifact upload actions until reviewed; GitHub publication remains a separate explicit user decision.
