"""Post-prediction review only: gold targets never become audit facts or mappings."""
import argparse,csv,json,re,sys
from collections import Counter,defaultdict
from dataclasses import asdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit.inputs import load_dataset
from audit.contracts import Request,Resource,timestamp
from audit.identity import Subject,identifier
from audit.timeline import reconstruct
from audit.policy import Policy
from audit.validate import supports_operation
from audit.extractors.documents import extract_text
from audit.reporting import json_default
from evaluation.metrics import evaluate,steps,CONTENT,FIELDS,counts


def run(root,baseline,output):
    data=load_dataset(root/'dataset',root/'.audit-cache','deletion_requests.csv')
    full=json.loads((baseline/'evaluation/runs/two_case_final/assessments.json').read_text())
    if full['input_hashes']!=data.input_hashes:raise ValueError('Baseline inputs changed')
    saved=json.loads((baseline/'evaluation/runs/two_case_samples/assessments.json').read_text())
    sample={c['case_id']:c for c in saved['cases']}
    actual=list(csv.DictReader((baseline/'evaluation/runs/two_case_samples/candidate_predictions.csv').open()))
    gold=list(csv.DictReader((root/'dataset/sample_output.csv').open()))
    request_rows=list(csv.DictReader((root/'dataset/sample_deletion_requests.csv').open()))
    requests={r['case_id']:Request.from_row(r) for r in request_rows}
    predicted={r['case_id']:r for r in actual};metrics=evaluate(gold,actual)
    corpus=[]
    for a in data.artifacts:
        p=root/'dataset'/a['file_path']
        text=extract_text(p.read_bytes(),p.suffix,root/'.audit-cache')[0] if p.suffix in {'.pdf','.png'} else p.read_text()
        corpus.append((a['file_id'],a['file_path'],timestamp(a['captured_at']),text))
    for name,id_key in [('system_activity.csv','activity_id'),('user_audit_log.csv','audit_id')]:
        for n,row in enumerate(csv.DictReader((root/'dataset'/name).open()),2):
            corpus.append((row[id_key],f'{name}:{n}',timestamp(row['event_time']),json.dumps(row,ensure_ascii=False)))
    fact_index=defaultdict(list)
    for f in data.facts:fact_index[f.resource].append(f)
    operation=Counter();category=Counter();root_causes=Counter();sources=Counter();cases=[];all_diffs=[]
    policy=Policy(data.rules)
    for g in gold:
        cid=g['case_id'];p=predicted.get(cid);c=sample[cid];req=requests[cid]
        subject=Subject(user_id=c['subject_id'],aliases=set(c['subject_aliases']),names=set(c['subject_names']))
        gs,ps=steps(g),steps(p);gc,pc=counts(gs,ps);diffs=[]
        for kind,values in [('missing',gc-pc),('extra',pc-gc)]:
            for v in values.elements():
                s=dict(zip(CONTENT,v));resource=Resource(s['system_id'],s['resource_id'])
                facts=fact_index[resource];admitted=[f for f in facts if f.admitted(req.audit_at)]
                linked=[f for f in admitted if any(identifier(v) in subject.aliases for v in f.links)]
                state=reconstruct(resource,data.facts,req.audit_at)
                obligation=policy.evaluate(state,subject,req.audit_at,data.facts)
                target_state=bool(state.observations) and all(supports_operation(f,s['operation'],subject) for f in state.observations)
                ref_state=any(f.evidence_id==s['evidence_id'] and f.kind=='OBSERVATION' and f.admitted(req.audit_at) and supports_operation(f,s['operation'],subject) for f in facts) if s['evidence_id'] else None
                pattern=re.compile(r'(?<!\w)'+re.escape(s['resource_id'])+r'(?!\w)')
                raw=[{'source_id':eid,'path':path,'available':when,'within_cutoff':when<=req.audit_at,'matching_lines':[n for n,line in enumerate(text.splitlines(),1) if pattern.search(line)]} for eid,path,when,text in corpus if pattern.search(text)]
                future=g['deletion_status']=='INCOMPLETE' and s['phase'] in {'REMEDIATION','VERIFICATION'}
                expected_operation={'REMEDIATION':obligation.remediation,'VERIFICATION':obligation.verification,'FINDING':obligation.finding}[s['phase']]
                supported_extra=bool(linked) and (target_state or (future and s['operation']==expected_operation)) and not any(i.code=='EXCLUSIVE_OWNERSHIP_UNPROVEN' for i in obligation.issues)
                if kind=='extra':cause='Supported additional resource omitted by canonical answer' if supported_extra else 'Extra resource needs independent review'
                elif not raw:cause='Genuine evidence insufficiency: identifier absent from searched participant corpus'
                elif not admitted:cause='Audit-time inventory gap: identifier appears only in future evidence'
                elif not linked:cause='Missing subject-to-resource relationship'
                elif any(i.code=='EXCLUSIVE_OWNERSHIP_UNPROVEN' for i in obligation.issues):cause='Policy condition: exclusive attachment ownership unproven'
                elif not target_state and g['deletion_status']=='COMPLETE':cause='Missing state evidence'
                else:cause='Incomplete verification inventory / independent review required'
                row={'case_id':cid,'kind':kind,'step':s,'policy_category':state.category or 'unknown','root_cause':cause,
                     'subject_link_supported':bool(linked),'current_target_state_supported':target_state,'current_state_required':g['deletion_status']=='COMPLETE',
                     'cited_state_supported':ref_state,'policy_issues':[asdict(i) for i in obligation.issues],
                     'admissible_facts':[asdict(f) for f in admitted],'raw_occurrences':raw}
                diffs.append(row);all_diffs.append(row)
                operation[(kind,s['operation'])]+=1;category[(kind,row['policy_category'])]+=1;root_causes[(kind,cause)]+=1
                for match in raw:sources[(kind,match['source_id'])]+=1
        field_diff=[]
        keys={(s['phase'],s['system_id'],s['resource_id']) for s in gs+ps}
        for key in sorted(keys):
            a=[s for s in gs if (s['phase'],s['system_id'],s['resource_id'])==key]
            b=[s for s in ps if (s['phase'],s['system_id'],s['resource_id'])==key]
            if len(a)==len(b)==1:
                mismatch={f:{'expected':a[0].get(f),'predicted':b[0].get(f)} for f in FIELDS if a[0].get(f)!=b[0].get(f)}
                if mismatch:field_diff.append({'key':key,'differences':mismatch})
        cases.append({'case_id':cid,'expected_status':g['deletion_status'],'predicted_status':p['deletion_status'] if p else None,
                      'expected_steps':gs,'predicted_steps':ps,'status_correct':p is not None and g['deletion_status']==p['deletion_status'],
                      'exact':p is not None and g['deletion_status']==p['deletion_status'] and gs==ps,'field_differences':field_diff,
                      'predicted_numbering_consecutive':all(s['step_no']==n for n,s in enumerate(ps,1)),
                      'subject_id':subject.user_id,'identity_issues':[i for i in c['issues'] if i['component']=='identity'],
                      'issues':c['issues'],'differences':diffs})
    # Gold-free review of every uncertain full-dataset verdict, including raw
    # alias hits not represented by extracted linked facts. This does not emit predictions.
    detail=json.loads((baseline/'evaluation/runs/two_case_final/candidate_diagnostics.json').read_text())
    assessments={c['case_id']:c for c in full['cases']};full_requests={r.case_id:r for r in data.requests};uncertain=[]
    for candidate in detail['cases']:
        if candidate['confidence'] in {'STRICT_RELEASE','PROVEN_INCOMPLETE_PARTIAL_PLAN'}:continue
        cid=candidate['case_id'];c=assessments[cid];req=full_requests[cid];aliases=set(c['subject_aliases'])
        aliases_re=re.compile(r'(?<![\w@.+-])(?:'+'|'.join(re.escape(a) for a in sorted(aliases,key=lambda a:-len(a)))+r')(?![\w@.+-])',re.I)
        linked=[f for f in data.facts if f.admitted(req.audit_at) and any(identifier(v) in aliases for v in f.links)]
        extracted_sources={f.evidence_id for f in linked}
        raw_unextracted=[]
        for eid,path,when,text in corpus:
            if when<=req.audit_at and eid not in extracted_sources and aliases_re.search(text):
                raw_unextracted.append({'source_id':eid,'path':path,'already_consumed_identity_metadata':path.startswith('user_audit_log.csv:'),'matching_lines':[line.strip()[:220] for line in text.splitlines() if aliases_re.search(line)][:8]})
        scope=[f for f in data.facts if f.kind=='SCOPE' and f.admitted(req.audit_at) and f.resource.system=='account_service' and f.fields.get('complete')]
        inventory=c['inventory'];known_false=[r for r in inventory if r['compliant'] is False]
        uncertain.append({'case_id':cid,'prediction':candidate['row']['deletion_status'],'confidence':candidate['confidence'],
                          'supported_as_full_compliance':False,'subject_id':c['subject_id'],'audit_at':req.audit_at,
                          'issue_codes':sorted({i['code'] for i in candidate['issues']}),'inventory':inventory,'known_noncompliant_inventory':known_false,
                          'admissible_linked_source_ids':sorted(extracted_sources),'complete_account_scope_ids':sorted({f.evidence_id for f in scope}),
                          'raw_alias_hits_without_extracted_link':raw_unextracted,'execution_preconditions':candidate.get('execution_preconditions',[])})
    result={'baseline_metrics':metrics,'cases':cases,'differences':all_diffs,'aggregates':{
        name:[{'kind':k[0],'value':k[1],'count':v} for k,v in sorted(counter.items())] for name,counter in [('operation',operation),('policy_category',category),('root_cause',root_causes),('source',sources)]},
        'uncertain_status_count':len(uncertain),'uncertain_complete_count':sum(c['prediction']=='COMPLETE' for c in uncertain),'uncertain_status_reviews':uncertain}
    output.parent.mkdir(parents=True,exist_ok=True);output.with_suffix('.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,default=json_default)+'\n')
    lines=['# Accuracy review: independent evidence and canonical comparison','','Gold supplies evaluation/search targets only; no mappings, identifiers, labels or facts from this report enter runtime prediction. Search covers all 94 evidence artifacts (text/PDF/OCR), full activity and identity-audit rows. Raw matches are leads, not ownership proof. Absence from this bounded search is not proof that all possible human interpretation is exhausted.','','## Baseline metrics','',f"Status {metrics['status_correct']}/32; exact {metrics['exact_cases']}/32; step precision {100*metrics['step_precision']:.4f}%; recall {100*metrics['step_recall']:.4f}%; field accuracy {100*metrics['field_accuracy']:.4f}%; sequence {100*metrics['sequence_accuracy']:.4f}%.",
           '',f"Missing steps: {sum((counts(steps(g),steps(predicted.get(g['case_id'])))[0]-counts(steps(g),steps(predicted.get(g['case_id'])))[1]).total() for g in gold)}. Extra steps: {sum(1 for d in all_diffs if d['kind']=='extra')}. Missing status predictions: {', '.join(c['case_id'] for c in cases if c['predicted_status'] is None)}. Incorrect emitted statuses: {', '.join(c['case_id'] for c in cases if c['predicted_status'] is not None and not c['status_correct']) or 'none'}.",
           '', '## Error aggregates','']
    for name,items in result['aggregates'].items():
        lines.extend([f'### {name}','','| Kind | Value | Count |','|---|---|---:|'])
        for x in items:lines.append(f"| {x['kind']} | {x['value']} | {x['count']} |")
        lines.append('')
    lines+=['## All 32 cases','']
    for c in cases:
        lines.extend([f"### {c['case_id']}",'',f"Expected status: {c['expected_status']}; predicted: {c['predicted_status'] or 'missing'}; exact: {c['exact']}. Subject: {c['subject_id']}. Predicted numbering consecutive: {c['predicted_numbering_consecutive']}.",'', 'Expected ordered steps:','', '```json',json.dumps(c['expected_steps'],ensure_ascii=False),'```','', 'Predicted ordered steps:','','```json',json.dumps(c['predicted_steps'],ensure_ascii=False),'```','', 'Field/number differences: '+json.dumps(c['field_differences'],ensure_ascii=False), '', 'Evidence/identity/coverage issues: '+', '.join(sorted({i['code'] for i in c['issues']}))])
        for d in c['differences']:
            s=d['step'];lines.extend(['',f"- {d['kind'].upper()} {s['phase']} {s['operation']} {s['system_id']}/{s['resource_id']} {s['state']} cite={s['evidence_id'] or '(future empty)'}: {d['root_cause']}. Subject link={d['subject_link_supported']}; current predicate={d['current_target_state_supported']}; current proof required={d['current_state_required']}. Sources: "+', '.join(f"{x['source_id']} ({'admissible capture' if x['within_cutoff'] else 'FUTURE excluded'})" for x in d['raw_occurrences'])])
    lines+=['','## All 157 uncertain full-dataset statuses','',f"Reviewed {len(uncertain)} statuses; {result['uncertain_complete_count']} are uncertain COMPLETE predictions. None is promoted to verified compliance. An empty or incomplete search does not prove COMPLETE. Existing sidecar confidence and case_55/63 execution restrictions remain mandatory.",'','| Case | Prediction | Known obligations | Issues | Raw alias leads not extracted as subject links |','|---|---|---|---|']
    for c in uncertain:
        lines.append(f"| {c['case_id']} | {c['prediction']} | "+', '.join(r['resource_id'] for r in c['inventory'])+' | '+', '.join(c['issue_codes'])+' | '+', '.join(x['source_id'] for x in c['raw_alias_hits_without_extracted_link'])+' |')
    output.write_text('\n'.join(lines)+'\n')
    print(json.dumps({'sample_status':metrics['status_correct'],'sample_exact':metrics['exact_cases'],'missing_steps':sum(d['kind']=='missing' for d in all_diffs),'extra_steps':sum(d['kind']=='extra' for d in all_diffs),'root_causes':result['aggregates']['root_cause'],'uncertain_statuses_reviewed':len(uncertain),'uncertain_complete':result['uncertain_complete_count'],'raw_unextracted_leads':sum(len(c['raw_alias_hits_without_extracted_link']) for c in uncertain)},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--baseline',type=Path,default=Path('artifacts/accuracy_baseline_locked'));parser.add_argument('--output',type=Path,default=Path('evaluation/accuracy_review.md'));args=parser.parse_args()
    run(Path(__file__).resolve().parents[2],args.baseline,args.output)
