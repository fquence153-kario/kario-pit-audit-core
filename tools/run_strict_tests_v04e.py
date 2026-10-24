"""Run full KARIO synthetic regressions with strict count and no skips."""
import sys
import unittest

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: run_strict_tests_v04e.py TEST_DIR')
    suite = unittest.TestLoader().discover(sys.argv[1], pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    expected = 182  # original 154 + new 28
    if not result.wasSuccessful() or result.testsRun != expected or result.skipped:
        raise SystemExit(f'KARIO v0.4E FAILED: run={result.testsRun}, skipped={len(result.skipped)}')
    print(f'KARIO v0.4E ALL {expected} TESTS PASSED')
