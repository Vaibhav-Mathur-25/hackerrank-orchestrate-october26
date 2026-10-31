"""Evaluate saved sample predictions in a separate process that may read gold."""
from __future__ import annotations
import argparse
import csv
from datetime import datetime
import json
import hashlib
from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluation.metrics import evaluate
from audit.contracts import timestamp, Assessment, Fact, Resource, Issue
from audit.serialize import atomic_write
from audit.validate import validate_steps, validate_assessment


def ledger_assessment(case,row,parsed):
    def fact(value):
        value=dict(value)
        value.update(observed=timestamp(value['observed']),available=timestamp(value['available']),
                     resource=Resource(**value['resource']),links=tuple(value['links']),coverage=frozenset(value['coverage']))
        return Fact(**value)
    proofs={}
    for proof in case['proofs']:
        facts=[]
        for value in proof['sources']:
            value=dict(value)
            value.update(observed=timestamp(value['observed']),available=timestamp(value['available']),
                         resource=Resource(**value['resource']),links=tuple(value['links']),coverage=frozenset(value['coverage']))
            facts.append(Fact(**value))
        proofs[(proof['system_id'],proof['resource_id'],proof['operation'])]=facts
    return Assessment(case_id=row['case_id'],status=row['deletion_status'],steps=parsed,
                      inventory=case['inventory'],proofs=proofs,subject_id=case['subject_id'],
                      issues=[Issue(**i) for i in case.get('issues',[])],discovery=case.get('discovery',{}),
                      relationship_proofs=[fact(f) for f in case.get('relationship_proofs',[])],
                      subject_aliases=set(case.get('subject_aliases',[])),subject_names=set(case.get('subject_names',[])))


def run(run_dir: Path,dataset: Path):
    with (dataset/"sample_output.csv").open(newline="") as f:gold=list(csv.DictReader(f))
    with (run_dir/"sample_predictions.csv").open(newline="") as f:predicted=list(csv.DictReader(f))
    payload=json.loads((run_dir/"assessments.json").read_text())
    if hashlib.sha256((run_dir/"sample_predictions.csv").read_bytes()).hexdigest()!=payload["predictions_sha256"]:
        raise ValueError("Prediction CSV does not match the recorded audit run")
    with (dataset/"sample_deletion_requests.csv").open(newline="") as f:requests={r["case_id"]:r for r in csv.DictReader(f)}
    references={}
    for name,id_key,time_key in [("evidence_files.csv","file_id","captured_at"),("system_activity.csv","activity_id","event_time"),("user_audit_log.csv","audit_id","event_time")]:
        with (dataset/name).open(newline="") as f:
            for r in csv.DictReader(f):references[r[id_key]]=timestamp(r[time_key])
    raw_predicted=predicted
    duplicates=Counter(r.get("case_id") for r in raw_predicted)
    predicted=[];structure_errors=[];semantic_errors=[];structural=valid_refs=ref_count=semantic_refs=0
    cases={c['case_id']:c for c in payload['cases']}
    for row in raw_predicted:
        try:
            if set(row)!={"case_id","deletion_status","steps_json"}:raise ValueError("Invalid prediction columns")
            if row["case_id"] not in requests:raise ValueError("Unexpected prediction case")
            if duplicates[row["case_id"]]!=1:raise ValueError("Duplicate prediction case")
            parsed=json.loads(row["steps_json"])
            validate_steps(row["deletion_status"],parsed)
        except (ValueError,TypeError,KeyError) as error:
            structure_errors.append({"case_id":row.get("case_id"),"error":str(error)})
            continue
        structural+=1
        cutoff=timestamp(requests[row['case_id']]['audit_at'])
        valid=True
        for step in parsed:
            eid=step['evidence_id']
            if not eid:continue
            ref_count+=1
            admissible=eid in references and references[eid]<=cutoff
            valid_refs+=int(admissible);valid &= admissible
        try:
            if not valid:raise ValueError('Unknown or post-cutoff citation')
            if not cases[row['case_id']]['resolved']:raise ValueError('Saved audit has unresolved obligations')
            validate_assessment(ledger_assessment(cases[row['case_id']],row,parsed),cutoff)
            semantic_refs+=sum(bool(s['evidence_id']) for s in parsed)
            predicted.append(dict(row,steps_json=parsed))
        except (ValueError,TypeError,KeyError) as error:
            semantic_errors.append({'case_id':row['case_id'],'error':str(error)})
    metrics=evaluate(gold,predicted)
    # Component evaluation uses gold only AFTER prediction to select the public
    # convention (current cited checks for COMPLETE, future checks otherwise).
    # These are not case predictions and never enter primary accuracy metrics.
    component=[];verification_gold=[]
    for target in gold:
        cid=target['case_id'];view='current_check' if target['deletion_status']=='COMPLETE' else 'planned_check'
        checks=[r[view] for r in cases[cid].get('verification_ledger',[]) if r.get(view)]
        component.append({'case_id':cid,'deletion_status':target['deletion_status'],'steps_json':checks})
        expected=json.loads(target['steps_json'])
        verification_gold.append(dict(target,steps_json=[s for s in expected if s['phase']=='VERIFICATION']))
    component_metrics=evaluate(verification_gold,component)
    metrics['verification_ledger_diagnostic']={k:component_metrics[k] for k in ['matched_steps','expected_steps','predicted_steps','step_precision','step_recall']}
    draft=[{"case_id":c["case_id"],"deletion_status":c["supported_status"],"steps_json":c["diagnostic_steps"]} for c in payload["cases"] if c["supported_status"]]
    draft_metrics=evaluate(gold,draft)
    metrics["diagnostic_draft_metrics"]={k:v for k,v in draft_metrics.items() if k!="mismatches"}
    gold_status={r["case_id"]:r["deletion_status"] for r in gold}
    supported=sum(c["supported_status"]==gold_status.get(c["case_id"]) for c in payload["cases"] if c["supported_status"])
    metrics.update(structurally_valid_rows=structural,structural_correctness=structural/len(raw_predicted) if raw_predicted else None,
                   structural_coverage=structural/len(gold),citation_references=ref_count,valid_citation_references=valid_refs,
                   citation_id_time_validity=valid_refs/ref_count if ref_count else None,
                   supported_status_correct=supported,supported_status_accuracy=supported/len(gold),
                   supported_status_decisions=sum(c["supported_status"] is not None for c in payload["cases"]),structure_errors=structure_errors,
                   semantic_errors=semantic_errors,semantic_ledger_valid_rows=len(predicted),
                   semantic_ledger_validity=len(predicted)/structural if structural else None,
                   semantic_ledger_citations=semantic_refs)
    candidate_path=run_dir/'candidate_predictions.csv'
    if candidate_path.exists():
        from audit.candidates import validate_candidate_steps
        candidate_report=json.loads((run_dir/'candidate_diagnostics.json').read_text())
        candidate_details={c['case_id']:c for c in candidate_report['cases']}
        if hashlib.sha256(candidate_path.read_bytes()).hexdigest()!=candidate_report['candidate_sha256']:raise ValueError('Candidate checksum mismatch')
        candidate_rows=[];candidate_errors=[]
        for row in csv.DictReader(candidate_path.open(newline='')):
            try:
                parsed=json.loads(row['steps_json'])
                review=candidate_details[row['case_id']]['confidence']
                validate_candidate_steps(ledger_assessment(cases[row['case_id']],row,parsed),row['deletion_status'],parsed,timestamp(requests[row['case_id']]['audit_at']),review=review if review.startswith('REVIEW_') else None)
                candidate_rows.append(dict(row,steps_json=parsed))
            except (ValueError,TypeError,KeyError) as error:candidate_errors.append({'case_id':row.get('case_id'),'error':str(error)})
        candidate_metrics=evaluate(gold,candidate_rows)
        metrics['best_effort_candidate_metrics']={k:v for k,v in candidate_metrics.items() if k!='mismatches'}
        metrics['best_effort_candidate_errors']=candidate_errors
        atomic_write(run_dir/'candidate_metrics.json',json.dumps(candidate_metrics,ensure_ascii=False,indent=2).encode())
    atomic_write(run_dir/"metrics.json",json.dumps(metrics,ensure_ascii=False,indent=2).encode())
    lines=["# Sample evaluation","",
           "Measured on the 32 supplied sample requests. This is not hidden-set accuracy or a final submission run.","",
           "Primary accuracy uses only fully resolved public predictions; unresolved cases count as failures in the 32-case denominator.","",
           "| Metric | Measured result |","|---|---:|"]
    for title,key in [("Status accuracy","status_accuracy"),("Exact case accuracy","exact_case_accuracy"),("Step precision","step_precision"),("Step recall","step_recall"),("Verification recall","verification_recall"),("Field accuracy","field_accuracy"),("Sequence accuracy","sequence_accuracy"),("Structural correctness among emitted rows","structural_correctness"),("Structural coverage over 32 cases","structural_coverage"),("Citation ID/time validity","citation_id_time_validity")]:
        value=metrics[key];lines.append(f"| {title} | {'N/A: no observations' if value is None else f'{value:.6%}'} |")
    lines.extend(["",f"Resolved predictions: {len(predicted)}/32. Exact cases: {metrics['exact_cases']}/32. Matched steps: {metrics['matched_steps']}/{metrics['expected_steps']} expected and {metrics['predicted_steps']} predicted.","",
                  f"Additional diagnostic measure: {supported}/32 statuses agree when including supported INCOMPLETE decisions with unresolved plans ({metrics['supported_status_decisions']} statuses decided). This is not public-output accuracy.","",
                  f"Field agreement: {metrics['correct_fields']}/{metrics['evaluated_fields']} fields. Citation existence/cutoff checks: {valid_refs}/{ref_count}.","",
                  "Citation ID/time validity does not independently establish semantic proof. The predictor additionally checks its source/resource proof ledger; ambiguity is reported, not assumed correct.","",
                  f"Semantic proof-ledger validation: {len(predicted)}/{structural} structurally valid rows accepted; {len(semantic_errors)} rejected. This rechecks state predicates and policy coverage using saved extraction facts; it is not an independent human review of every original artifact.","",
                  f"Independent verification component (diagnostic, not public accuracy): {component_metrics['matched_steps']}/{component_metrics['expected_steps']} expected checks matched. Known checks survive blocked case verdicts; this does not establish complete discovery or policy compliance.","",
                  f"Diagnostic draft steps (not publishable plans): precision {draft_metrics['step_precision']:.6%}, recall {draft_metrics['step_recall']:.6%}. These include unresolved obligations and must not be substituted for primary public-output metrics.","",
                  "## Metric definitions","",
                  "Step precision/recall use multisets of the six fields excluding step_no. Sequence requires the exact parsed array. Field alignment groups by phase/system/resource, prefers matching operations, then maximizes seven-field agreement; missing and extra steps contribute seven incorrect fields. Sample JSON object-key order is ignored.","",
                  "## Mismatches","",
                  "Case-specific missing/extra steps are saved in the evaluation-only metrics.json. The solver cannot read that file or sample_output.csv.",""])
    if 'best_effort_candidate_metrics' in metrics:
        c=metrics['best_effort_candidate_metrics']
        lines+=['## Qualified candidate evaluation','',
                f"Explicitly uncertain/partial-plan candidates: {c['predicted_cases']}/32 rows; {c['status_correct']}/32 statuses; {c['exact_cases']}/32 exact; step precision {c['step_precision']:.6%}, recall {c['step_recall']:.6%}. These metrics do not certify full plans or compliance. Strict release metrics above are unchanged.",'']
    cases={c["case_id"]:c for c in payload["cases"]}
    for mismatch in metrics["mismatches"]:
        cid=mismatch["case_id"];codes=sorted({i["code"] for i in cases[cid]["issues"]})
        lines.append(f"- {cid}: {', '.join(mismatch['categories'])}; diagnostics: {', '.join(codes) or 'inspect step/citation differences'}.")
    lines.extend(["","## Evaluation-only missing-resource investigation","",
                  "The following uses expected resource IDs only after prediction. It does not feed mappings back into the solver.",""])
    for mismatch in metrics["mismatches"]:
        cid=mismatch["case_id"]
        if not cases[cid]["resolved"]:continue
        inventory={(r["system_id"],r["resource_id"]) for r in cases[cid]["inventory"]}
        for missing in mismatch["missing_steps"]:
            key=(missing["system_id"],missing["resource_id"])
            if key in inventory:continue
            candidates=[f for f in payload.get("source_index",[]) if (f["system_id"],f["resource_id"])==key and timestamp(f["available"])<=timestamp(requests[cid]["audit_at"]) and timestamp(f["observed"])<=timestamp(requests[cid]["audit_at"])]
            refs=", ".join(f"{f['evidence_id']} ({f['locator']}, {f['kind']}, {'has links' if f['links'] else 'no identity links'})" for f in candidates)
            lines.append(f"- {cid}, `{missing['resource_id']}`: not discovered in subject inventory. Admissible candidates: {refs or 'none'}. Investigate resource linkage; do not copy the expected ID into prediction code.")
    atomic_write(run_dir/"evaluation_report.md","\n".join(lines).encode())
    return metrics


def main():
    parser=argparse.ArgumentParser(description="Evaluate existing sample predictions; never invokes the solver")
    root=Path(__file__).resolve().parents[2]
    parser.add_argument("--run-dir",type=Path,default=root/"evaluation/runs/baseline")
    parser.add_argument("--dataset",type=Path,default=root/"dataset")
    args=parser.parse_args();metrics=run(args.run_dir,args.dataset)
    print(json.dumps({k:v for k,v in metrics.items() if k not in {"mismatches","structure_errors"}},indent=2))


if __name__=="__main__":main()
