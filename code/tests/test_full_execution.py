import tempfile,unittest
from pathlib import Path
from audit.inputs import Inputs
from audit.intent import classify


class FullExecutionTest(unittest.TestCase):
    def test_full_requests_require_explicit_capability_and_gold_stays_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'deletion_requests.csv').write_text('case_id\nfictional\n')
            with self.assertRaises(PermissionError):Inputs(root).read('deletion_requests.csv')
            full=Inputs(root,'deletion_requests.csv')
            self.assertTrue(full.read('deletion_requests.csv'))
            with self.assertRaises(PermissionError):full.read('sample_output.csv')

    def test_surname_correction_is_non_deletion_but_explicit_deletion_wins(self):
        self.assertIs(classify('My name is misspelled. Please fix it without removing my records.').authorized,False)
        self.assertIs(classify('My name is misspelled. Please fix it and delete my account.').authorized,True)
