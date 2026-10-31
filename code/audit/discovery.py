"""Coverage review from source facts, independently of the planner's obligations.

Unattributed records are leads, never assigned by position. A lead that can hide
a relevant copy prevents a COMPLETE claim. Missing exact identifiers still block
plans that require those resources; they are never synthesized.
"""
import re
from .contracts import Issue
from .identity import identifier,pre_request_negative_probe


def profile_scope_queries(subject, admitted):
    """Retain subject-scoped negative evidence without inventing a former ID.

    A full exported table can prove no selector match at its snapshot time.
    That query is distinct from a resource-level ABSENT assertion and from
    case-wide compliance. It never supplies a resource to the identity graph.
    """
    if not subject.user_id:return []
    scopes=[f for f in admitted if f.kind=='SCOPE' and f.resource.system=='account_service'
            and f.category=='USER_PROFILE' and f.fields.get('complete')]
    observations={}
    for f in admitted:
        if f.kind=='OBSERVATION':observations.setdefault((f.evidence_id,f.store),[]).append(f)
    latest={}
    for scope in scopes:
        latest[scope.store]=max(latest.get(scope.store,scope.observed),scope.observed)
    scopes=[f for f in scopes if f.observed==latest[f.store]]
    aliases={identifier(a) for a in subject.aliases}|{identifier(subject.user_id)}
    def linked_to_subject(fact):
        return (any(isinstance(fact.fields.get(k),str) and identifier(fact.fields[k]) in aliases
                    for k in ['user_id','email','phone','email_hash']) or
                any(identifier(v) in aliases for v in fact.links))
    out=[]
    for scope in sorted(scopes,key=lambda f:(f.store,f.evidence_id,f.locator)):
        rows=[f for f in observations.get((scope.evidence_id,scope.store),[])
              if f.locator.startswith(scope.locator+'/') and f.category=='USER_PROFILE']
        covered={f.resource.resource_id for f in rows}==set(scope.fields['members'])
        # Nonempty rows need a real stable-key column; sparse mixed exports
        # cannot silently stand in for a full identity-keyed profile table.
        covered=covered and all(isinstance(f.fields.get('user_id'),str) and f.fields['user_id'] for f in rows)
        matches=[f for f in rows if linked_to_subject(f)]
        result='UNKNOWN' if not covered else 'MATCH' if matches else 'NO_MATCH'
        later=[]
        for f in admitted:
            if f.observed<=scope.observed:continue
            linked=linked_to_subject(f)
            if f.kind=='OBSERVATION' and f.resource.system=='account_service' and f.category=='USER_PROFILE' and linked and f.state!='ABSENT':later.append(f.evidence_id)
            affects=f.resource.system=='account_service' or f.fields.get('target_system')=='account_service'
            creates=f.fields.get('event_type') in {'CREATE_RECORD','UPDATE_RECORD','RESTORE_BACKUP','SYNC_RECORD'}
            if f.kind=='CLAIM' and affects and creates and (linked or not f.links):later.append(f.evidence_id)
        tied=[f for f in scopes if f.store==scope.store]
        conflict=len({tuple(sorted(f.fields['members'])) for f in tied})>1
        out.append({'evidence_id':scope.evidence_id,'locator':scope.locator,'store':scope.store,
                    'observed':scope.observed.isoformat(),'available':scope.available.isoformat(),
                    'selector_result':result,'matched_resource_ids':sorted({f.resource.resource_id for f in matches}),
                    'later_admissible_recreation_or_presence_sources':sorted(set(later)),
                    'equal_time_scope_conflict':conflict,
                    'supports_selector_absence_at_cutoff':result=='NO_MATCH' and not later and not conflict,
                    'supplies_former_resource_id':False})
    return out


def assess(subject, request, facts):
    admitted=[f for f in facts if f.admitted(request.audit_at)]
    aliases={identifier(a) for a in subject.aliases}
    linked=[f for f in admitted if f.resource.resource_id and any(identifier(v) in aliases for v in f.links)]
    excluded={f.resource for f in linked if pre_request_negative_probe(f.resource,subject,admitted,request.requested_at,request.audit_at)}
    historical=[{'system_id':f.resource.system,'resource_id':f.resource.resource_id,'evidence_id':f.evidence_id,
                 'observed':f.observed.isoformat(),'reason':'Pre-request lookup miss without independent membership/existence evidence'}
                for f in linked if f.resource in excluded]
    linked=[f for f in linked if f.resource not in excluded]
    required=sorted({f.resource for f in linked})
    artifacts={f.evidence_id for f in linked}
    unassigned=sorted({f.resource for f in admitted if f.evidence_id in artifacts and f.kind=='OBSERVATION'
                       and f.resource.resource_id and f.resource not in required and not f.links
                       and f.category in {'USER_PROFILE','ANALYTICS_PROFILE','PRODUCT_TELEMETRY'}})
    issues=[]
    if unassigned:
        issues.append(Issue('DISCOVERY_UNASSIGNED_RECORDS','coverage',
                            'Relevant source artifacts contain unassigned profile records; discovery is insufficient for COMPLETE.',
                            evidence_ids=tuple(sorted(artifacts)),effect='COMPLETE'))
    # A clearly restricted request does not require inventing an unrelated
    # primary account. Global account deletion still needs an account coverage
    # path; collection-level absence cannot manufacture a public resource ID.
    restricted=bool(re.fullmatch(r'\s*(?:please\s+)?(?:delete|remove)\s+only\s+(?:the\s+|my\s+)?(?:attachment|export|search result|marketing profile)[.!]?\s*',request.request_text,re.I))
    account_scopes=[f for f in admitted if f.kind=='SCOPE' and f.resource.system=='account_service' and f.category=='USER_PROFILE' and f.fields.get('complete')]
    if not restricted and not any(r.system=='account_service' for r in required):
        issues.append(Issue('ACCOUNT_COVERAGE_UNRESOLVED','coverage',
                            'Global deletion lacks an attributable account resource. A table-wide search can establish subject absence but cannot supply the former ID.',
                            evidence_ids=tuple(sorted({f.evidence_id for f in account_scopes}))))
    return {'required_resources':[{'system_id':r.system,'resource_id':r.resource_id} for r in required],
            'unassigned_resources':[{'system_id':r.system,'resource_id':r.resource_id} for r in unassigned],
            'reviewed_artifacts':sorted(artifacts),'account_scopes':[f.evidence_id for f in account_scopes],
            'profile_scope_queries':profile_scope_queries(subject,admitted),
            'excluded_historical_negative_queries':sorted(historical,key=lambda r:(r['system_id'],r['resource_id'],r['evidence_id'],r['observed'])),
            'request_scope':'restricted' if restricted else 'global'},issues


def validate_coverage(discovery,steps,status):
    if status=='NOT_APPLICABLE':return
    if not discovery:raise ValueError('Missing independent discovery assessment')
    required={(r['system_id'],r['resource_id']) for r in discovery['required_resources']}
    checks={(s['system_id'],s['resource_id']) for s in steps if s['phase']=='VERIFICATION'}
    if not required.issubset(checks):
        raise ValueError('Source discovery contains resources missing from verification')
    if status=='COMPLETE' and discovery['unassigned_resources']:
        raise ValueError('Unassigned profile records prevent COMPLETE')
