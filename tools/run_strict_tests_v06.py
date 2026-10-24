"""Strict v0.6 regression: 222 previous + 56 new; zero skips/failures."""
import sys
import unittest

EXPECTED = 222 + 56

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run_strict_tests_v06.py TEST_DIRECTORY")
    suite = unittest.TestLoader().discover(sys.argv[1], pattern="test_*.py")
    results = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not results.wasSuccessful() or results.testsRun != EXPECTED or results.skipped):
        raise SystemExit(
            f"KARIO v0.6 FAILED: ran={results.testsRun} expected={EXPECTED} "
            f"skipped={len(results.skipped)} errors={len(results.errors)} "
            f"failures={len(results.failures)}"
        )
    print(f"KARIO v0.6 ALL {EXPECTED} TESTS PASSED")
