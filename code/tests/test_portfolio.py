"""Independent safety and end-to-end checks for the public portfolio entry point."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from audit.planner import Auditor
from audit.portfolio import review_report
from audit.inputs import load_dataset
from fixtures import dataset, observed, request

ROOT = Path(__file__).resolve().parents[2]


class PortfolioTest(unittest.TestCase):
    def test_uncertain_backup_never_publishes_complete_or_steps(self):
        data = dataset([observed(), observed('backup_service', 'archive', 'BACKUP_ARCHIVE', 'PRESENT')])
        result = Auditor(data).audit(request())
        case = review_report([result], data)['cases'][0]
        self.assertTrue(case['review_required'])
        self.assertIsNone(case['deletion_status'])
        self.assertEqual(case['steps'], [])
        self.assertFalse(case['execution_authorized'])

    def test_disputed_ownership_withholds_delete_plan(self):
        data = dataset([observed(state='PRESENT', email='foreign@example.test')])
        result = Auditor(data).audit(request())
        case = review_report([result], data)['cases'][0]
        self.assertTrue(case['review_required'])
        self.assertTrue(case['actions_withheld'])
        self.assertIsNone(case['deletion_status'])
        self.assertEqual(case['steps'], [])
        self.assertTrue(any(i['component'] == 'identity' for i in case['issues']))

    def test_demo_exercises_real_ingestion_and_safety_boundaries(self):
        data = load_dataset(ROOT / 'demo/dataset', requests_file='deletion_requests.csv')
        self.assertEqual(len(data.artifacts), 4)
        self.assertTrue(all(a['status'] == 'parsed' for a in data.artifacts))
        report = review_report([Auditor(data).audit(r) for r in data.requests], data)
        cases = {r['case_id']: r for r in report['cases']}
        for case_id, status in [('changed_email', 'INCOMPLETE'), ('deleted', 'COMPLETE'),
                                ('correction', 'NOT_APPLICABLE'), ('future_ignored', 'INCOMPLETE')]:
            self.assertEqual(cases['demo_' + case_id]['deletion_status'], status)
        self.assertEqual(cases['demo_changed_email']['subject_id'], 'user_demoalpha')
        self.assertIn('marketing_demoalpha', {s['resource_id'] for s in cases['demo_changed_email']['steps']})
        for case_id in ['demo_disputed_owner', 'demo_restore_unknown']:
            self.assertTrue(cases[case_id]['review_required'])
            self.assertEqual(cases[case_id]['steps'], [])
        self.assertTrue(all(s['evidence_id'] != 'demo_future' for c in cases.values() for s in c['steps']))

    def test_demo_cli_is_repeatable_and_does_not_publish_competition_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            outputs = []
            for name in ['one', 'two']:
                run = subprocess.run([sys.executable, '-S', str(ROOT / 'code/main.py'), '--demo', '--run-dir', str(directory/name)],
                                     cwd=directory, capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                outputs.append((directory/name/'audit_report.json').read_bytes())
                self.assertFalse((directory/name/'output.csv').exists())
            self.assertEqual(*outputs)
            self.assertEqual(json.loads(outputs[0])['request_count'], 6)

    def test_conditional_candidate_requires_explicit_competition_mode(self):
        run = subprocess.run([sys.executable, str(ROOT/'code/main.py'), '--conditional-review'],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertIn('--competition-output', run.stderr)

    def test_ai_requires_explicit_model(self):
        run = subprocess.run([sys.executable, str(ROOT/'code/main.py'), '--ai-assisted'],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertIn('--gemini-model', run.stderr)
