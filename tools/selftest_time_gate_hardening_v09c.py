"""Standalone v0.9C regression tests; intentionally not named test_*.py.

The v0.9 strict test runner has a frozen expectation of 408 discovered tests.
Run this file separately after the original regression suite.
"""
from __future__ import annotations

import json
import unittest

from kario_pit.audit.time_gate import audit_time_gate


class TimeGateInputHardeningV09CTests(unittest.TestCase):
    def gate(self, **changes):
        params = {
            'evidence_id': 'SYN-TG-1',
            'decision_at': '2026-01-02T10:00:35Z',
            'availability_upper_at': '2026-01-02T10:00:05Z',
            'registered_latency_seconds': 30,
            'source_published_at': '2026-01-02T10:00:00Z',
        }
        params.update(changes)
        return audit_time_gate(**params)

    def test_equal_boundary_still_passes_unverified(self):
        r = self.gate()
        self.assertEqual(r['status'], 'TIME_GATE_PASS_UNVERIFIED')
        self.assertTrue(r['time_gate_pass'])
        self.assertIs(r['pit_certified'], False)
        self.assertEqual(r['policy_version'], 'KARIO_TIME_GATE_V0.1')

    def test_future_evidence_still_hold(self):
        self.assertEqual(self.gate(decision_at='2026-01-02T10:00:34Z')['status'], 'HOLD_AFTER_DECISION')

    def test_published_after_upper_remains_chronology_hold(self):
        self.assertEqual(self.gate(source_published_at='2026-01-02T10:00:06Z')['status'], 'HOLD_CHRONOLOGY_CONFLICT')

    def test_optional_published_none_is_permitted(self):
        self.assertEqual(self.gate(source_published_at=None)['status'], 'TIME_GATE_PASS_UNVERIFIED')

    def test_empty_published_rejected(self):
        r = self.gate(source_published_at='')
        self.assertEqual(r['status'], 'HOLD_INVALID_INPUT')
        self.assertFalse(r['time_gate_pass'])

    def test_boolean_published_rejected(self):
        self.assertEqual(self.gate(source_published_at=False)['status'], 'HOLD_INVALID_INPUT')

    def test_empty_availability_rejected(self):
        self.assertEqual(self.gate(availability_upper_at='')['status'], 'HOLD_INVALID_INPUT')

    def test_missing_availability_keeps_separate_hold(self):
        self.assertEqual(self.gate(availability_upper_at=None)['status'], 'HOLD_MISSING_AVAILABILITY')

    def test_invalid_timestamp_never_echoed(self):
        marker = 'PRIVATE_CUSTOMER_IDENTIFIER_123456'
        result = self.gate(decision_at=marker)
        self.assertEqual(result['status'], 'HOLD_INVALID_INPUT')
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(result.get('diagnostic'), 'INVALID_TIME_GATE_INPUT')

    def test_invalid_published_timestamp_never_echoed(self):
        marker = 'CUSTOMER_SECRET_DO_NOT_LOG'
        result = self.gate(source_published_at=marker)
        self.assertEqual(result['status'], 'HOLD_INVALID_INPUT')
        self.assertNotIn(marker, json.dumps(result))

    def test_invalid_evidence_id_redacted(self):
        marker = 'PRIVATE CUSTOMER ID'
        result = self.gate(evidence_id=marker)
        self.assertEqual(result['status'], 'HOLD_INVALID_INPUT')
        self.assertIsNone(result['evidence_id'])
        self.assertNotIn(marker, json.dumps(result))

    def test_oversize_evidence_id_rejected(self):
        result = self.gate(evidence_id='x'*129)
        self.assertEqual(result['status'], 'HOLD_INVALID_INPUT')
        self.assertIsNone(result['evidence_id'])

    def test_evidence_id_valid_128_characters(self):
        self.assertEqual(self.gate(evidence_id='x'*128)['status'], 'TIME_GATE_PASS_UNVERIFIED')

    def test_boolean_latency_rejected(self):
        self.assertEqual(self.gate(registered_latency_seconds=True)['status'], 'HOLD_INVALID_INPUT')

    def test_negative_latency_rejected(self):
        self.assertEqual(self.gate(registered_latency_seconds=-1)['status'], 'HOLD_INVALID_INPUT')

    def test_bad_timezone_rejected(self):
        self.assertEqual(self.gate(decision_at='2026-01-02T10:00:35')['status'], 'HOLD_INVALID_INPUT')

    def test_utc_offset_decision_equivalence(self):
        r = self.gate(decision_at='2026-01-02T21:00:35+11:00')
        self.assertEqual(r['status'], 'TIME_GATE_PASS_UNVERIFIED')

    def test_absurd_latency_fail_closed(self):
        r = self.gate(registered_latency_seconds=10**70)
        self.assertEqual(r['status'], 'HOLD_INVALID_INPUT')
        self.assertIs(r['pit_certified'], False)

    def test_all_invalid_cases_never_pit_certify(self):
        for opts in ({'source_published_at': False}, {'availability_upper_at': ''}, {'evidence_id': '\n'}):
            self.assertIs(self.gate(**opts)['pit_certified'], False)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TimeGateInputHardeningV09CTests))
    if result.wasSuccessful() and result.testsRun == 19 and not result.skipped:
        print('KARIO v0.9C ALL 19 HARDENING TESTS PASSED')
    else:
        raise SystemExit(1)
