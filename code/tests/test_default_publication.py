"""CLI publication success is separate from strict semantic release."""
import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import main as cli
from audit.serialize import csv_bytes


class DefaultPublicationTest(unittest.TestCase):
    def execute(self,root,options=(),mutation=None):
        count=32 if '--samples' in options else 518
        requests=[SimpleNamespace(case_id=f'fictional_{i:04}') for i in range(count)]
        data=SimpleNamespace(requests=requests,facts=[])
        rows=[{'case_id':q.case_id,'deletion_status':'NOT_APPLICABLE','steps_json':[]} for q in requests]
        if mutation:mutation(rows)
        candidate={'candidate_rows':len(rows),'cases':[{'row':row} for row in rows]}
        def write_run(directory,*args,**kwargs):
            directory.mkdir(parents=True,exist_ok=True)
            (directory/'resolved_predictions.csv').write_bytes(b'strict subset')
            return {'resolved_count':1}
        root.mkdir(exist_ok=True);(root/'output.csv').write_bytes(b'preserved champion')
        out=io.StringIO()
        with patch.object(cli,'__file__',str(root/'code/main.py')),patch('sys.argv',['code/main.py','--competition-output',*options]),\
             patch('audit.inputs.load_dataset',return_value=data),patch('audit.planner.Auditor') as auditor,\
             patch('audit.reporting.write_run',side_effect=write_run),patch('audit.candidates.write_candidates',return_value=candidate) as writer,contextlib.redirect_stdout(out):
            status=cli.main()
        return status,writer,out.getvalue(),requests,rows

    def test_no_argument_run_publishes_complete_candidate_and_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);status,writer,text,requests,rows=self.execute(root)
            self.assertEqual(status,0);self.assertIs(writer.call_args.args[-1],True)
            self.assertEqual((root/'output.csv').read_bytes(),csv_bytes(rows,{q.case_id for q in requests}))
            self.assertEqual((root/'output.verified.csv').read_bytes(),b'strict subset')
            self.assertIn('1/518 strict assessments resolved',text);self.assertIn('Semantic compliance is not certified',text)

    def test_partial_candidate_preserves_existing_output_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);status,*_=self.execute(root,mutation=lambda rows:rows.pop())
            self.assertEqual(status,2);self.assertEqual((root/'output.csv').read_bytes(),b'preserved champion')
            self.assertFalse((root/'output.verified.csv').exists())

    def test_wrong_case_set_or_invalid_steps_never_publish(self):
        def wrong_id(rows):rows[0]['case_id']='unexpected_case'
        def invalid_steps(rows):rows[0].update(deletion_status='COMPLETE',steps_json=[])
        for mutation in [wrong_id,invalid_steps]:
            with self.subTest(mutation=mutation.__name__),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);status,*_=self.execute(root,mutation=mutation)
                self.assertEqual(status,2);self.assertEqual((root/'output.csv').read_bytes(),b'preserved champion')

    def test_strict_exit_and_subset_behavior_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);status,writer,*_=self.execute(root,options=['--strict'])
            self.assertEqual(status,2);writer.assert_not_called();self.assertEqual((root/'output.csv').read_bytes(),b'strict subset')

    def test_samples_keep_existing_release_exit_and_explicit_review_behavior(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);status,writer,*_=self.execute(root,options=['--samples','--best-effort'])
            self.assertEqual(status,2);self.assertIs(writer.call_args.args[-1],False);self.assertEqual((root/'output.csv').read_bytes(),b'preserved champion')

    def test_diagnostic_full_candidate_succeeds_without_replacing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);status,*_=self.execute(root,options=['--diagnostic'])
            self.assertEqual(status,0);self.assertEqual((root/'output.csv').read_bytes(),b'preserved champion')


if __name__=='__main__':unittest.main()
