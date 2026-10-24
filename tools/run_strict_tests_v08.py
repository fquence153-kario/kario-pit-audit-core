"""v0.8 strict regression runner; abort on failures, skips, or a wrong test count."""
import sys
import unittest

EXPECTED = 371  # 318 v0.7 tests + 53 v0.8 tests

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: run_strict_tests_v08.py TEST_DIRECTORY')
    suite = unittest.TestLoader().discover(sys.argv[1], pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != EXPECTED or result.skipped:
        raise SystemExit(
            f'KARIO v0.8 FAILED: ran={result.testsRun} expected={EXPECTED} '
            f'skipped={len(result.skipped)} errors={len(result.errors)} failures={len(result.failures)}'
        )
    print('KARIO v0.8 ALL 371 TESTS PASSED')
