"""Offline forensic report. Gold is used only here, after saved predictions exist.

Never import this module from audit/. Resource searches below explain mismatches;
they do not produce relationships or predictions.
"""
import argparse
import csv
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit.inputs import load_dataset
from audit.identity import IdentityGraph
from audit.intent import classify
from audit.policy import Policy
from audit.timeline import reconstruct
from audit.extractors.documents import extract_text
from audit.reporting import json_default
from audit.serialize import atomic_write
from audit.contracts import timestamp
from evaluation.metrics import evaluate


def exact_occurrences(text, value):
    pattern=re.compile(r'(?<![\w@.+-])'+re.escape(value)+r'(?![\w@.+-])',re.I)
    return [(n,line.strip()) for n,line in enumerate(text.splitlines(),1) if pattern.search(line)]


def run(root, run_dir, output):
    payload=json.loads((run_dir/'assessments.json').read_text())
    data=load_dataset(root/'dataset',root/'.audit-cache')
    if data.input_hashes != payload['input_hashes']:
        raise ValueError('Forensic inputs differ from saved prediction inputs')
    gold=list(csv.DictReader((root/'dataset/sample_output.csv').open()))
    draft=[{'case_id':c['case_id'],'deletion_status':c['supported_status'],'steps_json':c['diagnostic_steps']} for c in payload['cases']]
    mismatch={m['case_id']:m for m in evaluate(gold,draft)['mismatches']}
    corpus=[]
    for a in data.artifacts:
        p=root/'dataset'/a['file_path']
        text=extract_text(p.read_bytes(),p.suffix,root/'.audit-cache')[0] if p.suffix in {'.pdf','.png'} else p.read_text()
        corpus.append((a['file_id'],a['file_path'],a['captured_at'],text))
    for name,id_key in [('system_activity.csv','activity_id'),('user_audit_log.csv','audit_id')]:
        for n,row in enumerate(csv.DictReader((root/'dataset'/name).open()),2):
            corpus.append((row[id_key],f'{name}:{n}',row['event_time'],json.dumps(row,ensure_ascii=False)))
    graph=IdentityGraph(data.identities,data.audits);policy=Policy(data.rules)
    cases={c['case_id']:c for c in payload['cases']}
    result=[]
    lines=['# Phase 4 forensic case reconstruction','',
           'All 32 cases are included, including every one of the original 29 blocked cases. This report is evaluation-only. Expected resource IDs are search terms for diagnosing omissions, never solver inputs.',
           '', 'Search scope: all 94 manifested artifacts (PDF text and PNG OCR included), activity, identity history, and the normalized relationship graph. Exact token boundaries prevent prefix collisions. A raw occurrence is a lead, not a proven relationship. Future captures remain excluded from decisions.',
           '', 'A = extraction omission; B = normalization/join defect; C = reasoning/validation defect; D = absent or contradictory support after the enumerated searches. D is bounded by this inspection, not proof that every possible human interpretation is exhausted.']
    for req in data.requests:
        current=cases[req.case_id];subject=graph.resolve(req.email,req.audit_at,data.facts,request_start=req.requested_at)
        bindings,_=graph.bindings(req.audit_at)
        chain={'case_id':req.case_id,'request':asdict(req),'intent':asdict(classify(req.request_text)),
               'subject_id':subject.user_id,'aliases':sorted(subject.aliases),
               'bindings':[asdict(b) for b in bindings if b.subject==subject.user_id],
               'resources':[],'issues':current['issues'],'resolved':current['resolved'],
               'diagnostic_steps':current['diagnostic_steps'],'evaluation_only_searches':[]}
        lines.extend(['',f'## {req.case_id}', '',f'Request: {req.request_text}', '',
                      f'Audit cutoff: `{req.audit_at.isoformat()}`. Intent: {classify(req.request_text).authorized}. Stable subject: `{subject.user_id}`.',
                      '',f'Current/historical identity values: {", ".join(f"`{a}`" for a in sorted(subject.aliases))}.',
                      '', 'Identity provenance: '+', '.join(sorted({b.evidence_id or 'user_identities.csv (snapshot at '+b.available.isoformat()+')' for b in bindings if b.subject==subject.user_id}))+'.',
                      '', '| Resource / category | Relationship evidence | State observations | Rule / target / compliance |', '|---|---|---|---|'])
        for resource in sorted(subject.resources):
            related=[f for f in data.facts if f.resource==resource and f.admitted(req.audit_at)]
            state=reconstruct(resource,data.facts,req.audit_at)
            obligation=policy.evaluate(state,subject,req.audit_at,data.facts)
            owners=[f for f in related if any(v.casefold() in {a.casefold() for a in subject.aliases} for v in f.links)]
            chain['resources'].append({'resource':asdict(resource),'relationships':[asdict(f) for f in owners],
                                       'observations':[asdict(f) for f in state.observations],
                                       'obligation':asdict(obligation)})
            relationships='; '.join(sorted({f'{f.evidence_id}:{f.locator} ({f.kind})' for f in owners})) or 'none'
            observations='; '.join(sorted({f'{f.evidence_id}:{f.locator} [{f.store}] {f.state} at {f.observed.isoformat()}' for f in state.observations})) or 'no admissible observation'
            lines.append(f'| `{resource.system}/{resource.resource_id}` / {state.category or "unknown"} | {relationships} | {observations} | {obligation.rule_id}: {obligation.verification or "unresolved"}; compliant={obligation.compliant} |')
        lines.extend(['','Publication blockers: '+('; '.join(f"{i['code']} ({i['resource_id'] or 'inventory'}): {i['message']}" for i in current['issues']) or 'none'),'',
                      'Generated diagnostic plan: '+('; '.join(f"{s['phase']} {s['operation']} {s['resource_id']} [{s['evidence_id'] or 'future check/action'}]" for s in current['diagnostic_steps']) or 'none')+'.'])
        diff=mismatch.get(req.case_id,{})
        lines.extend(['','Evaluation-only missing steps: '+json.dumps(diff.get('missing_steps',[])),
                      '', 'Evaluation-only extra steps: '+json.dumps(diff.get('extra_steps',[]))])
        targets={s['resource_id'] for s in diff.get('missing_steps',[])} | {i['resource_id'] for i in current['issues'] if i['resource_id']}
        for target in sorted(targets):
            matches=[]
            for eid,path,available,text in corpus:
                hits=exact_occurrences(text,target)
                if hits: matches.append({'evidence_id':eid,'path':path,'available':available,'admissible_capture':timestamp(available)<=req.audit_at,'hits':hits})
            facts=[f for f in data.facts if f.resource.resource_id==target]
            search={'resource_id':target,'occurrences':matches,'parsed_facts':[asdict(f) for f in facts]}
            chain['evaluation_only_searches'].append(search)
            lines.extend(['',f'Exact source search for `{target}`:'])
            if not matches:lines.append('- No literal resource ID in any searched artifact or activity/history row.')
            for m in matches:
                snippets='; '.join(f'line {n}: {s[:350]}' for n,s in m['hits'][:4])
                lines.append(f"- {m['evidence_id']} `{m['path']}` at {m['available']} ({'within cutoff' if m['admissible_capture'] else 'FUTURE, excluded'}): {snippets}")
            admissible=[f for f in facts if f.admitted(req.audit_at)]
            links=sorted({v for f in admissible for v in f.links})
            lines.append(f'- Parsed admissible facts: {len(admissible)}; identity links: {links or "none"}. A claim or unlinked 404 does not establish subject membership/state.')
        result.append(chain)
    output.parent.mkdir(parents=True,exist_ok=True)
    atomic_write(output,'\n'.join(lines).encode())
    atomic_write(output.with_suffix('.json'),json.dumps(result,ensure_ascii=False,indent=2,default=json_default).encode())
    print(f'Forensic chains: {len(result)}; report: {output}')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('evaluation/phase4_case_reconstruction.md'))
    args=parser.parse_args()
    run(Path(__file__).resolve().parents[2],args.run_dir,args.output)
