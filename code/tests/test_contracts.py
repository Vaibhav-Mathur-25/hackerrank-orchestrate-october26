import json
import unittest
from audit.contracts import Resource, make_step, order_steps, timestamp
from audit.serialize import csv_bytes
from audit.validate import validate_steps


class ContractsTest(unittest.TestCase):
    def complete(self):
        return order_steps([make_step("VERIFICATION", "VERIFY_RECORD_ABSENT", Resource("a", "r"), "file_x")])

    def test_round_trip_and_case_sort(self):
        rows = [{"case_id": k, "deletion_status": "COMPLETE", "steps_json": self.complete()} for k in ["case_2", "case_10"]]
        data = csv_bytes(rows, {"case_2", "case_10"}).decode()
        self.assertLess(data.index("case_10"), data.index("case_2"))
        self.assertEqual(data.encode(), csv_bytes(list(reversed(rows)), {"case_2", "case_10"}))

    def test_bad_steps_rejected(self):
        for field, value in [("state", "GONE"), ("step_no", True), ("step_no", 2), ("evidence_id", "")]:
            steps = self.complete(); steps[0][field] = value
            with self.assertRaises(ValueError): validate_steps("COMPLETE", steps)
        steps = self.complete(); steps[0]["extra"] = 1
        with self.assertRaises(ValueError): validate_steps("COMPLETE", steps)

    def test_non_deletion_and_coverage(self):
        validate_steps("NOT_APPLICABLE", [])
        with self.assertRaises(ValueError): validate_steps("NOT_APPLICABLE", self.complete())
        with self.assertRaises(ValueError): csv_bytes([], {"missing"})
        with self.assertRaises(ValueError): timestamp("2026-01-01")


if __name__ == "__main__": unittest.main()
