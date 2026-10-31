"""Independent, post-prediction review of each remaining canonical check.

Gold supplies diagnostic search targets only. This module produces no facts or
inputs consumed by audit/. A missing future-check citation is valid and is never
misreported as a missing current-state proof requirement.
"""
import argparse,csv,json,re
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit.inputs import load_dataset
from audit.contracts import timestamp,Resource
from audit.identity import identifier,Subject
from audit.timeline import reconstruct
from audit.validate import supports_operation
from audit.extractors.documents import extract_text
from audit.serialize import atomic_write


def signature(step):
    return tuple(step[k] for k in ['phase','system_id','resource_id','operation','state','evidence_id'])


def run(root,run_dir,output):
    data=load_dataset(root/'dataset',root/'.audit-cache')
    saved=json.loads((run_dir/'assessments.json').read_text())
    if data.input_hashes!=saved['input_hashes']:raise ValueError('Input hashes differ from saved audit')
    cases={c['case_id']:c for c in saved['cases']}
    before=json.loads((root/'evaluation/runs/phase46_final/assessments.json').read_text())
    baseline={c['case_id']:c for c in before['cases']}
    original=json.loads((root/'evaluation/phase46_verification_gaps.json').read_text())
    targets=[r for r in original['original_gaps'] if not r['recovered']]
    gold={r['case_id']:r for r in csv.DictReader((root/'dataset/sample_output.csv').open())}
    requests={r.case_id:r for r in data.requests}
    corpus=[]
    for item in data.artifacts:
        path=root/'dataset'/item['file_path']
        text=extract_text(path.read_bytes(),path.suffix,root/'.audit-cache')[0] if path.suffix in {'.pdf','.png'} else path.read_text()
        corpus.append((item['file_id'],item['captured_at'],text))
    reviews=[]
    lines=['# Verification recovery: review of all 50 remaining gaps','',
           'Gold is used only by this post-prediction reviewer. Current-state checks for COMPLETE require a cited, admissible readback. INCOMPLETE checks describe future work and correctly have empty citations; their resource attribution and policy target still require evidence.', '',
           '| Case | Resource / operation | Root cause at baseline | Subject link | Current target state | Reference / cutoff | Current ledger |','|---|---|---|---|---|---|---|']
    for target in targets:
        cid=target['case_id'];s=target['step'];case=cases[cid];request=requests[cid]
        subject=Subject(user_id=case['subject_id'],aliases=set(case['subject_aliases']),names=set(case['subject_names']))
        resource=Resource(s['system_id'],s['resource_id'])
        facts=[f for f in data.facts if f.resource==resource]
        admitted=[f for f in facts if f.admitted(request.audit_at)]
        linked=any(any(identifier(v) in subject.aliases for v in f.links) for f in admitted)
        state=reconstruct(resource,data.facts,request.audit_at)
        state_ok=bool(state.observations) and all(supports_operation(f,s['operation'],subject) for f in state.observations)
        ledger=case.get('verification_ledger',[])
        view='current_check' if gold[cid]['deletion_status']=='COMPLETE' else 'planned_check'
        recovered=any(r.get(view) and signature(r[view])==signature(s) for r in ledger)
        literal=[]
        pattern=re.compile(r'(?<!\w)'+re.escape(s['resource_id'])+r'(?!\w)')
        for eid,captured,text in corpus:
            if pattern.search(text):literal.append({'evidence_id':eid,'captured_at':captured,'admissible':timestamp(captured)<=request.audit_at})
        if recovered:category='Incomplete verification-inventory construction'
        elif not admitted and facts:category='Genuine evidence insufficiency: only post-cutoff resource evidence'
        elif not facts:category='Undiscovered resource / genuine evidence insufficiency' if not literal else 'Better extraction required'
        elif not linked:category='Missing subject-to-resource relationship'
        elif not state_ok:category='Missing state evidence'
        else:category='Verification evidence or citation disagreement'
        if s['evidence_id']:
            cited=[f for f in facts if f.evidence_id==s['evidence_id']]
            ref_ok=any(f.admitted(request.audit_at) and f.kind=='OBSERVATION' and supports_operation(f,s['operation'],subject) for f in cited)
            ref_note=f"{s['evidence_id']}: resource/state/cutoff {'supported' if ref_ok else 'not established'}"
        else:
            ref_ok=None;ref_note='Future check: empty reference is correct'
        row={'case_id':cid,'audit_at':request.audit_at.isoformat(),'expected_status':gold[cid]['deletion_status'],
             'step':s,'root_cause':category,'subject_supported':linked,'current_state_supported':state_ok,
             'current_state_required':gold[cid]['deletion_status']=='COMPLETE','referenced_state_supported':ref_ok,
             'ledger_recovered':recovered,'literal_sources':literal,
             'admissible_sources':[{'evidence_id':f.evidence_id,'locator':f.locator,'kind':f.kind,'state':f.state,'links':f.links,
                                    'observed':f.observed.isoformat(),'available':f.available.isoformat()} for f in admitted]}
        reviews.append(row)
        lines.append(f"| {cid} | {s['resource_id']} / {s['operation']} | {category} | {linked} | {state_ok} | {ref_note} | {'Recovered, diagnostic only' if recovered else 'Unresolved'} |")
    lines+=['','## Recurring patterns','']
    for category,count in sorted(Counter(r['root_cause'] for r in reviews).items()):lines.append(f'- {category}: {count}.')
    lines+=['','No newly inferred ownership, state, period or ID is written back into prediction. Ledger recovery records known checks in blocked cases; it does not publish a complete answer. False current-state support on a future check does not itself invalidate that future target.', '',
            '## All 24 previously blocked cases','',
            '| Case | Primary blocker / result | Fix class or remaining requirement |','|---|---|---|']
    for old in before['cases']:
        if old['resolved']:continue
        case=cases[old['case_id']]
        if case['resolved']:label='Resolved';action='Safe subject-scoped redaction preserves conversation; condition uncertainty still blocks COMPLETE'
        else:
            issues=[i for i in case['issues'] if i['blocking'] and i.get('effect')=='PUBLIC'] or case['issues']
            label=', '.join(sorted({i['code'] for i in issues}))
            if 'ACCOUNT_COVERAGE_UNRESOLVED' in label:action='Needs a pre-cutoff account/subject binding; known retained/process checks are now kept independently'
            elif 'EXCLUSIVE_OWNERSHIP_UNPROVEN' in label:action='Needs exclusive attachment ownership; destructive deletion remains blocked'
            elif 'CATEGORY_UNKNOWN' in label:action='Needs resource category and readback; reference-registry screen does not establish deleted status/full PII state'
            else:action='Needs admissible former-owner attribution for anonymous profile; never join by row position'
        lines.append(f"| {old['case_id']} | {label} | {action} |")
    atomic_write(output,'\n'.join(lines).encode())
    atomic_write(output.with_suffix('.json'),json.dumps(reviews,ensure_ascii=False,indent=2).encode())
    print(json.dumps({'reviewed':len(reviews),'diagnostic_ledger_recovered':sum(r['ledger_recovered'] for r in reviews),'remaining':sum(not r['ledger_recovered'] for r in reviews)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-dir',type=Path,default=Path('evaluation/runs/verification_final'))
    parser.add_argument('--output',type=Path,default=Path('evaluation/verification_evidence_review.md'))
    args=parser.parse_args();run(Path(__file__).resolve().parents[2],args.run_dir,args.output)
