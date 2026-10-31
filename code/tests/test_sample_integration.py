"""Actual sample-only process integration; no hardcoded sample predictions."""
import csv
import io
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import os

ROOT=Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('GHOST_CHALLENGE_TESTS') == '1',
                     'Requires an authorized challenge dataset and OCR dependencies; set GHOST_CHALLENGE_TESTS=1')
class SampleIntegrationTest(unittest.TestCase):
    def test_prediction_is_gold_isolated_and_deterministic(self):
        guard='''import os,sys,runpy
from pathlib import Path
def protect(event,args):
 if event=="open" and isinstance(args[0],(str,bytes,os.PathLike)):
  p=Path(os.fsdecode(args[0]))
  if p.name in {"sample_output.csv","deletion_requests.csv","output.csv","metrics.json","phase4_case_reconstruction.md","phase4_case_reconstruction.json","failure_inventory.md","phase46_verification_gaps.md","phase46_verification_gaps.json","verification_evidence_review.md","verification_evidence_review.json","verification_recovery_report.md"}:
   raise PermissionError("Forbidden prediction input: "+p.name)
sys.addaudithook(protect)
sys.path.insert(0,"code")
sys.argv=["code/main.py","--samples","--competition-output","--best-effort","--run-dir",sys.argv[1]]
runpy.run_path("code/main.py",run_name="__main__")
'''
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            first=subprocess.run([sys.executable,'-c',guard,str(directory/'one')],cwd=ROOT,capture_output=True,text=True,timeout=120)
            self.assertIn(first.returncode,[0,2],first.stderr)
            second=subprocess.run([sys.executable,'-c',guard,str(directory/'two')],cwd=ROOT,capture_output=True,text=True,timeout=120)
            self.assertEqual(first.returncode,second.returncode,second.stderr)
            one=json.loads((directory/'one/assessments.json').read_text())
            self.assertEqual(one['request_count'],32)
            self.assertEqual(len(one['cases']),32)
            self.assertEqual(len({c['case_id'] for c in one['cases']}),32)
            self.assertEqual(len(one['artifacts']),94)
            self.assertTrue(all(a['status']=='parsed' for a in one['artifacts']))
            self.assertNotIn('sample_output.csv',one['input_accesses'])
            self.assertEqual((directory/'one/sample_predictions.csv').read_bytes(),(directory/'two/sample_predictions.csv').read_bytes())
            self.assertEqual((directory/'one/candidate_predictions.csv').read_bytes(),(directory/'two/candidate_predictions.csv').read_bytes())

    def test_evaluator_counts_malformed_rows_as_failures(self):
        from evaluation.main import run
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            proc=subprocess.run([sys.executable,'code/main.py','--samples','--competition-output','--run-dir',str(directory)],cwd=ROOT,capture_output=True,text=True,timeout=120)
            self.assertIn(proc.returncode,[0,2],proc.stderr)
            payload=json.loads((directory/'assessments.json').read_text())
            csv_path=directory/'sample_predictions.csv'
            rows=list(csv.DictReader(io.StringIO(csv_path.read_text())))
            # If no cases resolve in a future version, construct a malformed row
            # using an actual requested ID, without importing its expected label.
            if not rows:rows=[{'case_id':payload['cases'][0]['case_id'],'deletion_status':'COMPLETE','steps_json':'{'}]
            else:rows[0]['steps_json']='{'
            stream=io.StringIO(newline='');writer=csv.DictWriter(stream,fieldnames=['case_id','deletion_status','steps_json']);writer.writeheader();writer.writerows(rows)
            encoded=stream.getvalue().encode();csv_path.write_bytes(encoded)
            payload['predictions_sha256']=hashlib.sha256(encoded).hexdigest()
            (directory/'assessments.json').write_text(json.dumps(payload))
            metrics=run(directory,ROOT/'dataset')
            self.assertEqual(metrics['cases'],32)
            self.assertTrue(metrics['structure_errors'])
            self.assertLess(metrics['structural_correctness'],1)


if __name__=='__main__':unittest.main()
