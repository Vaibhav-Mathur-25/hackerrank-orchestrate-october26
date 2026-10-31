"""Check a saved full output and report coverage failure without hiding it."""
import argparse,csv,json,hashlib,sys
from pathlib import Path
from audit.contracts import timestamp
from audit.validate import validate_steps,validate_assessment
from audit.serialize import atomic_write
from evaluation.main import ledger_assessment


def validate(root,output,run_dir,candidate=False):
    dataset=root/'dataset'
    requests={r['case_id']:r for r in csv.DictReader((dataset/'deletion_requests.csv').open())}
    payload=json.loads((run_dir/'assessments.json').read_text());cases={c['case_id']:c for c in payload['cases']}
    candidate_report=json.loads((run_dir/'candidate_diagnostics.json').read_text()) if candidate else None
    candidate_details={c['case_id']:c for c in candidate_report['cases']} if candidate else {}
    refs={}
    for name,key,time in [('evidence_files.csv','file_id','captured_at'),('system_activity.csv','activity_id','event_time'),('user_audit_log.csv','audit_id','event_time')]:
        for r in csv.DictReader((dataset/name).open()):refs[r[key]]=timestamp(r[time])
    with output.open(newline='',encoding='utf-8') as f:
        reader=csv.DictReader(f);header=reader.fieldnames;rows=list(reader)
    errors=[];seen=set();citations=0
    if header!=['case_id','deletion_status','steps_json']:errors.append('Wrong header')
    if [r['case_id'] for r in rows]!=sorted(r['case_id'] for r in rows):errors.append('Rows not sorted')
    for r in rows:
        try:
            cid=r['case_id']
            if cid in seen:raise ValueError('Duplicate case')
            seen.add(cid)
            if cid not in requests:raise ValueError('Unexpected case')
            parsed=json.loads(r['steps_json']);validate_steps(r['deletion_status'],parsed)
            cutoff=timestamp(requests[cid]['audit_at'])
            for s in parsed:
                if s['evidence_id']:
                    citations+=1
                    if s['evidence_id'] not in refs or refs[s['evidence_id']]>cutoff:raise ValueError('Unknown/future citation')
            assessed=ledger_assessment(cases[cid],r,parsed)
            if candidate:
                from audit.candidates import validate_candidate_steps,review_preconditions
                detail=candidate_details[cid];review=detail['confidence'] if detail['confidence'].startswith('REVIEW_') else None
                if review and detail.get('execution_preconditions')!=review_preconditions(review,assessed.subject_id):raise ValueError('Missing conditional execution guards')
                validate_candidate_steps(assessed,r['deletion_status'],parsed,cutoff,review=review)
            else:
                if not cases[cid]['resolved']:raise ValueError('Case is not released by its audit')
                validate_assessment(assessed,cutoff)
        except (ValueError,KeyError,TypeError) as e:errors.append(f"{r.get('case_id')}: {e}")
    missing=sorted(set(requests)-seen)
    if missing:errors.append(f'Missing {len(missing)} required cases')
    for name,digest in payload['input_hashes'].items():
        if hashlib.sha256((dataset/name).read_bytes()).hexdigest()!=digest:errors.append(f'Input changed: {name}')
    report={'required_rows':len(requests),'output_rows':len(rows),'unique_rows':len(seen),
            'row_errors':[e for e in errors if not e.startswith('Missing ')],
            'missing_case_ids':missing,'citation_count':citations,'errors':errors,
            'valid_full_submission':not errors and len(rows)==518,
            'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
    report['validation_mode']='candidate_assertions' if candidate else 'strict_release'
    report['structurally_valid_full_submission']=not errors and len(rows)==518
    if candidate:
        if report['output_sha256']!=candidate_report['candidate_sha256']:
            report['errors'].append('Candidate output checksum mismatch');report['valid_full_submission']=False
            report['structurally_valid_full_submission']=False
        report['confidence_counts']=candidate_report['confidence_counts']
        report['conditional_execution_restricted_cases']=[c['case_id'] for c in candidate_report['cases'] if c['confidence'].startswith('REVIEW_')]
        report['semantically_certified_full_submission']=False
        report['limitations']='COMPLETE labels are predictions over observed scope; INCOMPLETE candidates may have missing plan details. Row-level assertion checks are not full semantic validation.'
    atomic_write(run_dir/'output_validation.json',json.dumps(report,indent=2).encode())
    print(json.dumps({k:v for k,v in report.items() if k!='missing_case_ids'},indent=2))
    return report


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,default=root/'output.csv')
    p.add_argument('--run-dir',type=Path,default=root/'evaluation/runs/full_final')
    p.add_argument('--candidate',action='store_true')
    a=p.parse_args();r=validate(root,a.output,a.run_dir,a.candidate);sys.exit(0 if r['valid_full_submission'] else 2)
