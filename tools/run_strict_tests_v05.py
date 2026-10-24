"""Strict v0.5 test runner: fixed count, zero skips/failures; source tests intact."""
from __future__ import annotations

import sys
import unittest

EXPECTED = 182 + 40  # prior v0.4E + new v0.5 tests

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run_strict_tests_v05.py TEST_DIRECTORY")
    suite = unittest.TestLoader().discover(sys.argv[1], pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.testsRun != EXPECTED or result.skipped):
        raise SystemExit(
            f"KARIO v0.5 FAILED: run={result.testsRun} expected={EXPECTED} "
            f"skipped={len(result.skipped)} errors={len(result.errors)} failures={len(result.failures)}"
        )
    print(f"KARIO v0.5 ALL {EXPECTED} TESTS PASSED")
