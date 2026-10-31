"""Evaluation-only accounting of baseline omissions; never imported by audit."""
import argparse,csv,json
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluation.metrics import counts,steps,evaluate
from audit.contracts import timestamp
from audit.serialize import atomic_write


def run(dataset,before,after,output):
    gold=list(csv.DictReader((dataset/'sample_output.csv').open()))
    old=json.loads((before/'assessments.json').read_text())
    new=json.loads((after/'assessments.json').read_text())
    old_cases={c['case_id']:c for c in old['cases']};new_cases={c['case_id']:c for c in new['cases']}
    requests={r['case_id']:r for r in csv.DictReader((dataset/'sample_deletion_requests.csv').open())}
    rows=[];extra=[]
    fields=('phase','system_id','resource_id','operation','state','evidence_id')
    for g in gold:
        cid=g['case_id'];b=old_cases[cid];a=new_cases[cid]
        expected=counts(steps(g),[])[0]
        previous=counts(b['diagnostic_steps'] if b['supported_status'] else [],[])[0]
        current=counts(a['diagnostic_steps'] if a['supported_status'] else [],[])[0]
        cutoff=timestamp(requests[cid]['audit_at'])
        for signature,n in (expected-previous).items():
            if signature[0]!='VERIFICATION':continue
            s=dict(zip(fields,signature));key=(s['system_id'],s['resource_id'])
            candidates=[f for f in new['source_index'] if (f['system_id'],f['resource_id'])==key]
            admitted=[f for f in candidates if timestamp(f['available'])<=cutoff and timestamp(f['observed'])<=cutoff]
            recovered=bool(current[signature])
            if recovered:reason='Recovered through grounded link and scoped snapshot/readback'
            elif not candidates:reason='No normalized participant resource occurrence; no ID may be synthesized'
            elif not admitted:reason='Only post-cutoff normalized sources'
            elif not any(f['links'] for f in admitted):reason='No admissible subject relationship (claim or anonymous/unlinked readback)'
            elif any((i['system_id'],i['resource_id'])==key for i in a['inventory']):
                reason='Known verification target; case verdict remains blocked by unresolved discovery/conditions'
            else:reason='Relationship does not establish an executable verification obligation; inspect case diagnostics'
            rows.append(dict(case_id=cid,step=s,baseline_missing_count=n,recovered=recovered,reason=reason,candidates=candidates))
        for signature,n in (current-expected).items():
            s=dict(zip(fields,signature))
            refs=[f for f in new['source_index'] if (f['system_id'],f['resource_id'])==(s['system_id'],s['resource_id'])]
            extra.append(dict(case_id=cid,step=s,count=n,sources=refs))
    lines=['# Phase 4.6 verification gap accounting','',
           'Evaluation-only: every verification step missing from the original diagnostic drafts is listed. Expected IDs are search terms after prediction, never runtime discovery inputs. Counted recovery is draft recovery, not automatically public output.', '',
           '| Case | Resource | Check | Recovered | Remaining reason |','|---|---|---|---|---|']
    for r in rows:lines.append(f"| {r['case_id']} | {r['step']['resource_id']} | {r['step']['operation']} | {r['recovered']} | {r['reason']} |")
    lines+=['',f"Original missing verification steps: {sum(r['baseline_missing_count'] for r in rows)}. Recovered original omissions: {sum(r['baseline_missing_count'] for r in rows if r['recovered'])}.",
            '', '## Remaining extra diagnostic steps','',
            'Extra means disagreement with canonical output, not automatically unsupported. No extra step is present in final published predictions. The object-storage catalog/image supports an additional exclusive attachment; an earlier account readback supports a separate account ID. These leads cannot be removed solely to match labels. Full references appear in the JSON companion.']
    for r in extra:lines.append(f"- {r['case_id']}: {r['step']['operation']} {r['step']['system_id']}/{r['step']['resource_id']}; source candidates: {', '.join(sorted({f['evidence_id'] for f in r['sources']}))}.")
    lines+=['','## Regression accounted for','',
            'The previous COMPLETE draft for an incomplete discovery scope is now withdrawn. Its previously matched verification steps are not counted as new missing members of the original 51, but reduce current diagnostic recall. This is intentional evidence conservatism, not a parser regression.']
    atomic_write(output,'\n'.join(lines).encode())
    atomic_write(output.with_suffix('.json'),json.dumps({'original_gaps':rows,'extra_drafts':extra},ensure_ascii=False,indent=2).encode())
    print(json.dumps({'original_missing_verifications':len(rows),'recovered':sum(r['recovered'] for r in rows),'extra_draft_steps':sum(r['count'] for r in extra)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--before',type=Path,default=Path('evaluation/runs/phase4_final'))
    parser.add_argument('--after',type=Path,default=Path('evaluation/runs/phase46_final'))
    parser.add_argument('--dataset',type=Path,default=Path('dataset'))
    parser.add_argument('--output',type=Path,default=Path('evaluation/phase46_verification_gaps.md'))
    args=parser.parse_args();run(args.dataset,args.before,args.after,args.output)
