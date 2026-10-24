"""KARIO v0.9 offline test runner: count, passes, skips strictly enforced."""
import sys
import unittest

EXPECTED = 408  # 371 v0.8 + 37 v0.9 synthetic packaging / CLI tests

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: run_strict_tests_v09.py TEST_DIRECTORY')
    suite = unittest.TestLoader().discover(sys.argv[1], pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != EXPECTED or result.skipped:
        raise SystemExit(f'KARIO v0.9 FAILED: ran={result.testsRun} expected={EXPECTED} '
                         f'skipped={len(result.skipped)} errors={len(result.errors)} '
                         f'failures={len(result.failures)}')
    print('KARIO v0.9 ALL 408 TESTS PASSED')
