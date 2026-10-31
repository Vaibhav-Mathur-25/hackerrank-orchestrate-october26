"""Explicit best-effort predictions, separate from evidence-certified release.

Ordinary candidates require cited compliant-state observations for known policy
obligations. Opt-in conditional review can emit presence-only or ownership-gated
predictions; their unresolved predicates and execution restrictions are retained
in diagnostics. These predictions are not strict semantic releases.
"""
from collections import Counter
from dataclasses import dataclass,field
from .contracts import order_steps,make_step,Resource
from .identity import Subject,identifier
from .validate import validate_steps,supports_operation
from .policy import TARGETS


COMPLETE_ASSUMPTIONS={'ACCOUNT_COVERAGE_UNRESOLVED','DISCOVERY_UNASSIGNED_RECORDS',
                      'RETENTION_CONDITION_UNKNOWN','SHARED_CONTEXT_UNPROVEN',
                      'CATEGORY_UNKNOWN','NO_STATE_OBSERVATION'}


@dataclass
class Candidate:
    row: dict | None
    confidence: str
    strict_released: bool
    issues: list=field(default_factory=list)
    excluded_resources: list=field(default_factory=list)
    plan_complete: bool=False
    execution_preconditions: list=field(default_factory=list)


REVIEW_BACKUP='REVIEW_COMPLETE_RETAINED_ARCHIVE_RESTORE_UNKNOWN'
REVIEW_OWNER='REVIEW_INCOMPLETE_CONFLICTING_OWNERSHIP'


def review_preconditions(kind,subject_id):
    if kind==REVIEW_BACKUP:
        return ['Unverified COMPLETE prediction: archive presence does not establish restore safety.',
                'Obtain an admissible restore-policy readback before certifying compliance; do not infer ACTIVE or BLOCKED.']
    if kind==REVIEW_OWNER:
        return [f'Before any DELETE_RECORD, independently confirm the current exclusive owner is {subject_id}.',
                'If ownership is another customer or remains disputed, DO NOT DELETE; preserve that customer data.',
                'The INCOMPLETE label adopts the supplied catalog target conditionally; it is not a proven ownership conclusion.']
    raise ValueError('Unknown review category')


def _review_steps(result,cutoff,kind):
    """Only observed facts enter assertions; missing policy facts stay missing."""
    if len(result.inventory)!=1:raise ValueError('Review requires a single grounded obligation')
    r=result.inventory[0];key=(r['system_id'],r['resource_id']);resource=Resource(*key)
    links=[f for f in result.relationship_proofs if f.kind=='LINK' and f.resource==resource and f.admitted(cutoff)
           and any(identifier(v) in result.subject_aliases for v in f.links)]
    if not links:raise ValueError('Review lacks an explicit admissible catalog relationship')
    if kind==REVIEW_BACKUP:
        if r['category']!='BACKUP_ARCHIVE' or r['action']!='RETAIN' or r['compliant'] is not None:
            raise ValueError('Unknown-restore review cannot override known compliance or a violation')
        proofs=result.proofs.get((*key,'VERIFY_RECORD_PRESENT'),[])
        if any(type(f.fields.get('restore_allowed')) is bool or f.state in {'ACTIVE','BLOCKED'} for f in proofs):
            raise ValueError('Restore state is supplied; do not use unknown-restore review')
        valid=[f for f in proofs if f.kind=='OBSERVATION' and f.admitted(cutoff) and f.state=='PRESENT'
               and not f.fields.get('extraction_uncertain') and any(identifier(v) in result.subject_aliases for v in f.links)]
        if not valid:raise ValueError('No admissible, attributed archive-presence readback')
        source=min(valid,key=lambda f:(-f.observed.timestamp(),f.evidence_id,f.locator))
        return 'COMPLETE',order_steps([make_step('VERIFICATION','VERIFY_RECORD_PRESENT',resource,source.evidence_id)])
    if kind==REVIEW_OWNER:
        if r['category']!='MARKETING_PROFILE' or r['action']!='DELETE':raise ValueError('Review cannot invent a treatment rule')
        if not any(i.code=='RESOURCE_IDENTIFIER_CONFLICT' and i.resource_id==resource.resource_id for i in result.issues):
            raise ValueError('No explicit ownership conflict to review')
        proofs=result.proofs.get((*key,'REPORT_REMAINING_RECORD'),[])
        valid=[f for f in proofs if f.kind=='OBSERVATION' and f.admitted(cutoff) and f.state=='PRESENT'
               and (not f.fields.get('extraction_uncertain') or
                    (f.fields.get('uncertain_values') and all(resource.resource_id not in v for v in f.fields['uncertain_values'])))]
        # An uncertain email can affect ownership without invalidating the exact
        # resource ID printed in the selected panel. It is NOT repaired or used
        # as evidence that the displayed customer is the deletion subject.
        if not valid:raise ValueError('Record presence itself is not established')
        source=min(valid,key=lambda f:(-f.observed.timestamp(),f.evidence_id,f.locator))
        return 'INCOMPLETE',order_steps([
            make_step('FINDING','REPORT_REMAINING_RECORD',resource,source.evidence_id),
            make_step('REMEDIATION','DELETE_RECORD',resource),
            make_step('VERIFICATION','VERIFY_RECORD_ABSENT',resource)])
    raise ValueError('Unknown review category')


def choose_review_candidate(result,cutoff):
    for kind in [REVIEW_BACKUP,REVIEW_OWNER]:
        try:status,steps=_review_steps(result,cutoff,kind)
        except ValueError:continue
        validate_candidate_steps(result,status,steps,cutoff,review=kind)
        issues=[{'code':i.code,'resource_id':i.resource_id,'effect':i.effect} for i in result.issues if i.blocking]
        return Candidate({'case_id':result.case_id,'deletion_status':status,'steps_json':steps},kind,False,issues,
                         plan_complete=False,execution_preconditions=review_preconditions(kind,result.subject_id))
    return None


def choose_candidate(result,cutoff):
    issues=[{'code':i.code,'resource_id':i.resource_id,'effect':i.effect} for i in result.issues if i.blocking]
    if result.resolved:
        return Candidate({'case_id':result.case_id,'deletion_status':result.status,'steps_json':result.steps},'STRICT_RELEASE',True,issues,[],True)
    subject=Subject(user_id=result.subject_id,aliases=result.subject_aliases,names=result.subject_names)
    if not subject.user_id:return Candidate(None,'UNRESOLVED',False,issues)
    if result.status=='INCOMPLETE':
        # Only per-resource safety problems exclude a grounded action. Global
        # unknown-account coverage is disclosed as an incomplete plan, never
        # filled with a fabricated verification ID.
        unsafe={i.resource_id for i in result.issues if i.prevents('INCOMPLETE') and i.resource_id}
        inventory={(r['system_id'],r['resource_id']):r for r in result.inventory}
        steps=[s for s in result.steps if s['resource_id'] not in unsafe]
        try:
            validate_steps('INCOMPLETE',order_steps(steps))
            validate_candidate_steps(result,'INCOMPLETE',order_steps(steps),cutoff)
        except ValueError:return Candidate(None,'UNRESOLVED_UNSAFE_PLAN',False,issues,sorted(unsafe))
        return Candidate({'case_id':result.case_id,'deletion_status':'INCOMPLETE','steps_json':order_steps(steps)},
                         'PROVEN_INCOMPLETE_PARTIAL_PLAN',False,issues,sorted(unsafe),False)
    # A candidate COMPLETE is a prediction over observed resources, not verified
    # universal compliance. Unknown/unattributed copies and retention conditions
    # remain recorded. Any known noncompliant or unverified obligation blocks it.
    codes={i.code for i in result.issues if i.blocking}
    ledger=result.verification_ledger
    if not ledger or not codes.issubset(COMPLETE_ASSUMPTIONS) or any(not r['current_check'] for r in ledger):
        return Candidate(None,'UNRESOLVED',False,issues)
    steps=order_steps([r['current_check'] for r in ledger])
    try:validate_candidate_steps(result,'COMPLETE',steps,cutoff)
    except ValueError:return Candidate(None,'UNRESOLVED',False,issues)
    return Candidate({'case_id':result.case_id,'deletion_status':'COMPLETE','steps_json':steps},
                     'INFERRED_COMPLETE_OBSERVED_SCOPE',False,issues,[],False)


def validate_candidate_steps(result,status,steps,cutoff,review=None):
    """Validate assertions/actions without claiming complete discovery."""
    validate_steps(status,steps)
    if review:
        expected_status,expected_steps=_review_steps(result,cutoff,review)
        if status!=expected_status or steps!=expected_steps:raise ValueError('Conditional candidate differs from grounded review pattern')
        return
    inventory={(r['system_id'],r['resource_id']):r for r in result.inventory}
    subject=Subject(user_id=result.subject_id,aliases=result.subject_aliases,names=result.subject_names)
    for s in steps:
        key=(s['system_id'],s['resource_id'])
        if key not in inventory:raise ValueError('Ungrounded candidate resource')
        r=inventory[key]
        targets=TARGETS.get(r.get('action'))
        if r['category']=='DATA_FLOW':targets=('DISABLE_DATA_FLOW','VERIFY_DATA_FLOW_DISABLED','REPORT_ACTIVE_DATA_FLOW')
        if r['category']=='BACKUP_ARCHIVE':targets=('BLOCK_RESTORE','VERIFY_RESTORE_BLOCKED','REPORT_RESTORE_RISK')
        expected=targets[{'REMEDIATION':0,'VERIFICATION':1,'FINDING':2}[s['phase']]] if targets else None
        if s['operation']!=expected:raise ValueError('Unsupported candidate policy operation')
        if s['phase']!='VERIFICATION' and r['compliant'] is not False:raise ValueError('Unsupported candidate violation')
        if any(i.resource_id==s['resource_id'] and i.prevents(status) and i.code not in COMPLETE_ASSUMPTIONS for i in result.issues):
            raise ValueError('Unsafe resource condition')
        if s['evidence_id']:
            proofs=result.proofs.get((*key,s['operation']),[])
            valid=[f for f in proofs if f.kind=='OBSERVATION' and f.admitted(cutoff) and not f.fields.get('extraction_uncertain')
                   and f.resource.system==s['system_id'] and f.resource.resource_id==s['resource_id'] and supports_operation(f,s['operation'],subject)]
            if not any(f.evidence_id==s['evidence_id'] for f in valid):raise ValueError('Unsupported candidate citation')
            if status=='COMPLETE' and len(valid)!=len(proofs):raise ValueError('Incomplete or contradictory state proof')
    # Every emitted finding must keep its matching action and future check.
    for s in steps:
        if s['phase']!='FINDING':continue
        key=(s['system_id'],s['resource_id'])
        if not all(any((x['system_id'],x['resource_id'])==key and x['phase']==phase for x in steps) for phase in ['REMEDIATION','VERIFICATION']):
            raise ValueError('Partial candidate action triple')


def build_candidates(assessments,requests,conditional_review=False):
    by_id={r.case_id:r for r in requests}
    candidates={r.case_id:choose_candidate(r,by_id[r.case_id].audit_at) for r in assessments}
    if conditional_review:
        for result in assessments:
            if candidates[result.case_id].row:continue
            reviewed=choose_review_candidate(result,by_id[result.case_id].audit_at)
            if reviewed:candidates[result.case_id]=reviewed
    return candidates


def write_candidates(directory,assessments,requests,conditional_review=False):
    from dataclasses import asdict
    import json,hashlib
    from .serialize import csv_bytes,atomic_write
    candidates=build_candidates(assessments,requests,conditional_review)
    rows=[c.row for c in candidates.values() if c.row]
    encoded=csv_bytes(rows,{r['case_id'] for r in rows})
    atomic_write(directory/'candidate_predictions.csv',encoded)
    report={'request_count':len(requests),'candidate_rows':len(rows),
            'conditional_review_enabled':conditional_review,
            'missing_case_ids':sorted(cid for cid,c in candidates.items() if not c.row),
            'confidence_counts':dict(Counter(c.confidence for c in candidates.values())),
            'status_counts':dict(Counter(c.row['deletion_status'] for c in candidates.values() if c.row)),
            'structural_full_coverage':len(rows)==len(requests),
            'candidate_sha256':hashlib.sha256(encoded).hexdigest(),
            'cases':[dict(case_id=cid,**asdict(c)) for cid,c in sorted(candidates.items())]}
    atomic_write(directory/'candidate_diagnostics.json',json.dumps(report,ensure_ascii=False,indent=2).encode())
    lines=['# Best-effort candidate diagnostics','',
           f"Candidate rows: {len(rows)}/{len(requests)}. Strictly released rows are separately retained in the original audit. This file does not certify complete discovery or full semantic compliance.",
           '', 'Confidence categories: '+str(report['confidence_counts']),
           '', 'Missing cases: '+', '.join(report['missing_case_ids']),
           '', '| Case | Public prediction | Evidence category | Plan complete | Excluded resources | Remaining issues / execution preconditions |','|---|---|---|---|---|---|']
    for cid,c in sorted(candidates.items()):
        lines.append(f"| {cid} | {c.row['deletion_status'] if c.row else 'withheld'} | {c.confidence} | {c.plan_complete} | {', '.join(c.excluded_resources)} | {', '.join(sorted({i['code'] for i in c.issues}))}; {' '.join(c.execution_preconditions)} |")
    atomic_write(directory/'candidate_diagnostics.md','\n'.join(lines).encode())
    return report
