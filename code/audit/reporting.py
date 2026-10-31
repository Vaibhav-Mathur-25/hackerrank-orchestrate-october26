"""Development diagnostics. These files are explicitly not submission predictions."""
from dataclasses import asdict
from datetime import datetime
from collections import Counter
import json
import hashlib
from pathlib import Path
from .serialize import atomic_write, csv_bytes


def json_default(value):
    if isinstance(value, datetime): return value.isoformat()
    if isinstance(value, (set, frozenset)): return sorted(value)
    raise TypeError(type(value).__name__)


def write_run(directory, assessments, dataset, elapsed, mode="samples", model_usage=None):
    directory.mkdir(parents=True, exist_ok=True)
    resolved = [r for r in assessments if r.resolved]
    rows = [{"case_id":r.case_id,"deletion_status":r.status,"steps_json":r.steps} for r in resolved]
    encoded=csv_bytes(rows,{r.case_id for r in resolved})
    filename="sample_predictions.csv" if mode=="samples" else "resolved_predictions.csv"
    atomic_write(directory/filename,encoded)
    payload = {"mode":mode, "request_count":len(assessments), "resolved_count":len(resolved),
               "status_counts":dict(Counter(r.status or 'UNRESOLVED' for r in assessments)),
               "unresolved_count":sum(not r.resolved for r in assessments),
               "elapsed_seconds":elapsed, "runtime_model_calls":0, "runtime_input_tokens":0, "runtime_output_tokens":0,
               "input_accesses":dataset.accessed, "artifacts":dataset.artifacts,
               "input_hashes":dataset.input_hashes,
               "predictions_sha256":hashlib.sha256(encoded).hexdigest(),
               "ingestion_issues":[asdict(i) for i in dataset.issues], "cases":[]}
    if model_usage is not None:
        payload.update(runtime_model_calls=model_usage['http_attempts'],runtime_successful_model_calls=model_usage['successful_model_calls'],
                       runtime_input_tokens=model_usage['input_tokens'],runtime_output_tokens=model_usage['output_tokens'],
                       runtime_total_tokens=model_usage['total_tokens'],runtime_model_usage=model_usage)
    code_root=Path(__file__).resolve().parents[1]
    digest=hashlib.sha256()
    for path in sorted([code_root/"main.py",*Path(__file__).parent.rglob("*.py")]):
        digest.update(path.relative_to(code_root).as_posix().encode()+b"\0"+path.read_bytes())
    payload["prediction_source_sha256"]=digest.hexdigest()
    payload["source_index"]=[{"system_id":f.resource.system,"resource_id":f.resource.resource_id,
                              "evidence_id":f.evidence_id,"locator":f.locator,"observed":f.observed,"available":f.available,
                              "kind":f.kind,"links":f.links,"state":f.state,"category":f.category}
                             for f in dataset.facts if f.resource.resource_id]
    for r in assessments:
        proofs = [{"system_id":k[0],"resource_id":k[1],"operation":k[2],"sources":[asdict(f) for f in v]} for k,v in sorted(r.proofs.items())]
        payload["cases"].append({"case_id":r.case_id,"resolved":r.resolved,"supported_status":r.status,
                                 "subject_id":r.subject_id,"diagnostic_steps":r.steps,"inventory":r.inventory,
                                 "subject_aliases":sorted(r.subject_aliases),"subject_names":sorted(r.subject_names),
                                 "gates":r.gates,"discovery":r.discovery,
                                 "verification_ledger":r.verification_ledger,
                                 "relationship_proofs":[asdict(f) for f in r.relationship_proofs],
                                 "issues":[asdict(i) for i in r.issues],"proofs":proofs})
    atomic_write(directory/"assessments.json",json.dumps(payload,ensure_ascii=False,indent=2,default=json_default).encode())
    lines=["# Sample diagnostic report", "",f"Resolved public rows: {len(resolved)}/{len(assessments)}. The partial CSV is not a submission output.","",
           "Internal supported INCOMPLETE statuses can coexist with unresolved plans; these do not become public CSV rows.","",
           "## Evidence extraction", "",f"Artifacts decoded: {sum(a['status']=='parsed' for a in dataset.artifacts)}/{len(dataset.artifacts)}.","",
           "Decoded means an adapter ran. Partial visual/entity extraction remains explicitly flagged below.",""]
    for issue in dataset.issues:
        lines.append(f"- **{issue.code}** ({', '.join(issue.evidence_ids)}): {issue.message} Next: {issue.investigation}")
    for r in assessments:
        lines.extend(["",f"## {r.case_id}","",f"Resolved: {r.resolved}; supported status: {r.status or 'UNRESOLVED'}; subject: {r.subject_id or 'unresolved'}.",""])
        unique = {(i.code,i.component,i.resource_id,i.message,i.evidence_ids):i for i in r.issues}
        if not unique: lines.append("No blocking diagnostics.")
        for issue in unique.values():
            lines.append(f"- **{issue.code}** [{issue.effect}] — {issue.component}, resource `{issue.resource_id or 'not established'}`, evidence {', '.join(issue.evidence_ids) or 'missing'}: {issue.message} Next: {issue.investigation}")
    atomic_write(directory/"diagnostics.md","\n".join(lines).encode())
    return payload
