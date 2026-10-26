import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit.contract import step, order_and_number, validate_row
from audit.intent import requests_deletion


class ContractTests(unittest.TestCase):
    def test_ordering_and_numbering(self):
        steps = order_and_number([
            step("VERIFY_RECORD_ABSENT", "b", "2"), step("DELETE_RECORD", "a", "9"),
            step("REPORT_RESTORE_RISK", "z", "1", "act_1"), step("REPORT_REMAINING_RECORD", "b", "1", "e1"),
            step("DISABLE_DATA_FLOW", "a", "1"), step("REPORT_REMAINING_RECORD", "a", "1", "e2")])
        self.assertEqual([s["operation"] for s in steps], [
            "REPORT_REMAINING_RECORD", "REPORT_REMAINING_RECORD", "REPORT_RESTORE_RISK",
            "DISABLE_DATA_FLOW", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])
        self.assertEqual([s["system_id"] for s in steps[:2]], ["a", "b"])
        self.assertEqual([s["step_no"] for s in steps], list(range(1, 7)))
        self.assertEqual(validate_row("c", "INCOMPLETE", steps), [])

    def test_validation_catches_errors(self):
        self.assertTrue(validate_row("c", "NOT_APPLICABLE", order_and_number([step("DELETE_RECORD", "a", "1")])))
        self.assertTrue(validate_row("c", "COMPLETE", order_and_number([step("VERIFY_RECORD_ABSENT", "a", "1")])))  # no evidence
        self.assertTrue(validate_row("c", "INCOMPLETE", order_and_number([step("REPORT_REMAINING_RECORD", "a", "1", "e"), step("DELETE_RECORD", "a", "1", "oops")])))

    def test_dedupe(self):
        self.assertEqual(len(order_and_number([step("DELETE_RECORD", "a", "1"), step("DELETE_RECORD", "a", "1")])), 1)


class IntentTests(unittest.TestCase):
    def test_cases(self):
        yes = ["Please delete my account.", "I want to be forgotten, erase everything", "Supprimez mon compte svp", "アカウントを削除してください"]
        no = ["Send me a copy of my data", "Please do not delete my account", "Unsubscribe me from marketing", "Update my phone number"]
        for t in yes:
            self.assertTrue(requests_deletion(t), t)
        for t in no:
            self.assertFalse(requests_deletion(t), t)


if __name__ == "__main__":
    unittest.main()
