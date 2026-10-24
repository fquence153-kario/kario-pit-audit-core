"""KARIO v0.7 strict full-suite regression: 278 previous + 40 new, zero skip."""
import sys
import unittest

EXPECTED = 318

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run_strict_tests_v07.py TEST_DIRECTORY")
    suite = unittest.TestLoader().discover(sys.argv[1], pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != EXPECTED or result.skipped:
        raise SystemExit(
            f"KARIO v0.7 FAILED: ran={result.testsRun} expected={EXPECTED} "
            f"skipped={len(result.skipped)} errors={len(result.errors)} "
            f"failures={len(result.failures)}"
        )
    print("KARIO v0.7 ALL 318 TESTS PASSED")
