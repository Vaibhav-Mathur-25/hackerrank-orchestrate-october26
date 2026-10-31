import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluation.metrics import evaluate,field_alignment
from audit.contracts import make_step,order_steps,Resource


class EvaluationTest(unittest.TestCase):
    def rows(self):
        s=order_steps([make_step("VERIFICATION","VERIFY_RECORD_ABSENT",Resource("account_service","a"),"f")])
        return [{"case_id":"fictional","deletion_status":"COMPLETE","steps_json":s}]

    def test_exact_and_missing(self):
        rows=self.rows();m=evaluate(rows,rows)
        self.assertEqual(m["exact_case_accuracy"],1)
        self.assertEqual(m["field_accuracy"],1)
        m=evaluate(rows,[])
        self.assertEqual(m["status_accuracy"],0)
        self.assertEqual(m["step_recall"],0)
        self.assertEqual(m["field_accuracy"],0)

    def test_field_mismatch_and_citation(self):
        g=self.rows();p=self.rows();p[0]["steps_json"][0]["evidence_id"]="other"
        m=evaluate(g,p)
        self.assertEqual(m["status_accuracy"],1)
        self.assertEqual(m["step_precision"],0)
        self.assertAlmostEqual(m["field_accuracy"],6/7)

    def test_extra_step_penalized(self):
        g=self.rows();p=self.rows();p[0]["steps_json"].append(dict(p[0]["steps_json"][0],step_no=2))
        m=evaluate(g,p)
        self.assertEqual(m["step_precision"],.5)
        self.assertEqual(m["step_recall"],1)
        self.assertEqual(m["field_accuracy"],.5)

    def test_evaluator_rejects_semantically_invalid_citation(self):
        import csv,json,hashlib,tempfile
        from dataclasses import asdict
        from audit.planner import Auditor
        from audit.reporting import write_run,json_default
        from evaluation.main import run
        from fixtures import dataset,request,START
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=dataset();req=request();data.requests=[req]
            result=Auditor(data).audit(req)
            write_run(root/'run',[result],data,0)
            (root/'sample_output.csv').write_bytes((root/'run/sample_predictions.csv').read_bytes())
            rows={
                'sample_deletion_requests.csv':[json.loads(json.dumps(asdict(req),default=json_default))],
                'evidence_files.csv':[{'file_id':'fixture_fixture_account','captured_at':START}],
                'system_activity.csv':[{'activity_id':'unrelated','event_time':START}],
                'user_audit_log.csv':[{'audit_id':'unrelated_audit','event_time':START}]}
            for name,values in rows.items():
                with (root/name).open('w',newline='') as f:
                    w=csv.DictWriter(f,fieldnames=list(values[0]));w.writeheader();w.writerows(values)
            first=run(root/'run',root)
            self.assertEqual(first['exact_cases'],1)
            path=root/'run/assessments.json';payload=json.loads(path.read_text())
            payload['cases'][0]['proofs'][0]['sources'][0]['state']='PRESENT'
            path.write_text(json.dumps(payload))
            second=run(root/'run',root)
            self.assertEqual(second['structurally_valid_rows'],1)
            self.assertEqual(second['predicted_cases'],0)
            self.assertEqual(second['status_accuracy'],0)
            self.assertTrue(second['semantic_errors'])


if __name__=="__main__":unittest.main()
