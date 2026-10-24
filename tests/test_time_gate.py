import unittest

from kario_pit.audit.time_gate import audit_time_gate


class TimeGateTests(unittest.TestCase):

    def run_case(self, **changes):
        row = {
            "evidence_id": "SYNTHETIC-001",
            "source_published_at": "2026-01-02T10:00:00Z",
            "availability_upper_at": "2026-01-02T10:00:05Z",
            "registered_latency_seconds": 30,
            "decision_at": "2026-01-02T10:00:35Z",
        }
        row.update(changes)
        return audit_time_gate(**row)

    def test_equal_boundary_pass(self):
        r = self.run_case()
        self.assertTrue(r["time_gate_pass"])
        self.assertFalse(r["pit_certified"])

    def test_late_evidence_hold(self):
        r = self.run_case(
            decision_at="2026-01-02T10:00:34Z"
        )
        self.assertEqual(r["status"], "HOLD_AFTER_DECISION")

    def test_missing_availability_hold(self):
        r = self.run_case(availability_upper_at=None)
        self.assertEqual(
            r["status"], "HOLD_MISSING_AVAILABILITY"
        )

    def test_naive_timestamp_rejected(self):
        r = self.run_case(
            decision_at="2026-01-02T10:00:35"
        )
        self.assertEqual(r["status"], "HOLD_INVALID_INPUT")

    def test_chronology_conflict(self):
        r = self.run_case(
            source_published_at="2026-01-02T10:00:06Z"
        )
        self.assertEqual(
            r["status"], "HOLD_CHRONOLOGY_CONFLICT"
        )

    def test_negative_latency(self):
        r = self.run_case(
            registered_latency_seconds=-1
        )
        self.assertEqual(r["status"], "HOLD_INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
