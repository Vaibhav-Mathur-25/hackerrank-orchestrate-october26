"""Independent metrics with explicit handling of missing/unresolved predictions."""
from collections import Counter, defaultdict
from functools import lru_cache
import json

FIELDS=("step_no","phase","system_id","resource_id","operation","state","evidence_id")
CONTENT=FIELDS[1:]


def steps(row):
    value=row.get("steps_json",[]) if row else []
    return json.loads(value) if isinstance(value,str) else value


def counts(expected,predicted):
    return Counter(tuple(s.get(k) for k in CONTENT) for s in expected),Counter(tuple(s.get(k) for k in CONTENT) for s in predicted)


def field_alignment(expected,predicted):
    """Maximize matching fields inside grounded phase/system/resource groups."""
    left,right=defaultdict(list),defaultdict(list)
    for target,bucket in [(expected,left),(predicted,right)]:
        for s in target:bucket[tuple(s.get(k) for k in ["phase","system_id","resource_id"])].append(s)
    correct=units=0
    for key in sorted(set(left)|set(right),key=str):
        a,b=left[key],right[key]
        if len(a)>len(b):a,b=b,a
        @lru_cache(None)
        def solve(i,used):
            if i==len(a):return (0,0)
            choices=[]
            for j,r in enumerate(b):
                if used & (1<<j):continue
                suffix=solve(i+1,used|(1<<j))
                operation=int(a[i].get("operation")==r.get("operation"))
                matches=sum(a[i].get(k)==r.get(k) for k in FIELDS)
                choices.append((operation+suffix[0],matches+suffix[1]))
            return max(choices) if choices else (0,0)
        correct+=solve(0,0)[1]
        units+=max(len(a),len(b))*len(FIELDS)
    return correct,units


def evaluate(gold,predicted):
    expected={r["case_id"]:r for r in gold}
    actual={r["case_id"]:r for r in predicted}
    if len(expected)!=len(gold) or len(actual)!=len(predicted):raise ValueError("Duplicate case in evaluation input")
    status=exact=sequence=tp=total_gold=total_pred=fc=fu=0
    mismatches=[]
    phase_counts={p:{"matched":0,"expected":0,"predicted":0} for p in ("FINDING","REMEDIATION","VERIFICATION")}
    for cid,g in expected.items():
        p=actual.get(cid)
        gs,ps=steps(g),steps(p)
        status_ok=p is not None and p["deletion_status"]==g["deletion_status"]
        seq_ok=p is not None and gs==ps
        status+=int(status_ok);sequence+=int(seq_ok);exact+=int(status_ok and seq_ok)
        gc,pc=counts(gs,ps);tp+=sum((gc&pc).values());total_gold+=sum(gc.values());total_pred+=sum(pc.values())
        for phase,values in phase_counts.items():
            values['matched']+=sum(n for key,n in (gc&pc).items() if key[0]==phase)
            values['expected']+=sum(n for key,n in gc.items() if key[0]==phase)
            values['predicted']+=sum(n for key,n in pc.items() if key[0]==phase)
        c,u=field_alignment(gs,ps);fc+=c;fu+=u
        if not(status_ok and seq_ok):
            categories=[]
            if p is None:categories.append("unresolved_or_missing_prediction")
            elif not status_ok:categories.append("status")
            if gc!=pc:categories.append("step_content_or_citation")
            elif not seq_ok:categories.append("sequence_or_numbering")
            mismatches.append({"case_id":cid,"categories":categories,
                               "missing_steps":[dict(zip(CONTENT,v)) for v in (gc-pc).elements()],
                               "extra_steps":[dict(zip(CONTENT,v)) for v in (pc-gc).elements()]})
    n=len(gold)
    return {"cases":n,"predicted_cases":len(actual),"status_correct":status,"status_accuracy":status/n if n else 0,
            "exact_cases":exact,"exact_case_accuracy":exact/n if n else 0,"sequence_correct":sequence,"sequence_accuracy":sequence/n if n else 0,
            "matched_steps":tp,"expected_steps":total_gold,"predicted_steps":total_pred,
            "step_precision":tp/total_pred if total_pred else 0,"step_recall":tp/total_gold if total_gold else int(not total_pred),
            "correct_fields":fc,"evaluated_fields":fu,"field_accuracy":fc/fu if fu else 1,
            "unexpected_case_ids":sorted(set(actual)-set(expected)),"mismatches":mismatches,
            "phase_counts":phase_counts,
            "verification_recall":phase_counts['VERIFICATION']['matched']/phase_counts['VERIFICATION']['expected'] if phase_counts['VERIFICATION']['expected'] else 1}
