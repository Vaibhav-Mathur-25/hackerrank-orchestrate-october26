"""Checks cover all relevant obligations, including already-compliant resources."""
from .contracts import make_step, order_steps
from .citations import choose


def build_ledger(obligations, subject, cutoff):
    """Keep required checks even when a global verdict cannot be published.

    A current readback proves only its state predicate. Policy compliance and
    overall case completeness remain independent; conditional retention is not
    silently upgraded to compliant. Future targets never assert current state.
    """
    from .validate import supports_operation
    rows=[]
    for o in obligations:
        if not o.verification:continue
        proofs=[f for f in o.proof if f.kind=='OBSERVATION' and f.admitted(cutoff) and not f.fields.get('extraction_uncertain')]
        proven=bool(proofs) and len(proofs)==len(o.proof) and all(supports_operation(f,o.verification,subject) for f in proofs)
        rows.append({'system_id':o.resource.system,'resource_id':o.resource.resource_id,
                     'planned_check':make_step('VERIFICATION',o.verification,o.resource),
                     'current_check':make_step('VERIFICATION',o.verification,o.resource,choose(proofs,cutoff)) if proven else None,
                     'current_state_supported':proven,'policy_compliant':o.compliant,
                     'policy_issues':[i.code for i in o.issues],
                     'sources':[{'evidence_id':f.evidence_id,'locator':f.locator,'observed':f.observed,'available':f.available,'store':f.store} for f in proofs]})
    # Check numbers are local to each independent diagnostic view. They never
    # enter the public case array without ordinary case validation.
    for name in ['planned_check','current_check']:
        numbered=order_steps([r[name] for r in rows if r[name]])
        by_resource={(s['system_id'],s['resource_id']):s for s in numbered}
        for row in rows:
            if row[name]:row[name]=by_resource[(row['system_id'],row['resource_id'])]
    return rows


def verification_steps(obligations, status, cutoff):
    return [make_step("VERIFICATION", o.verification, o.resource,
                      choose(o.proof, cutoff) if status == "COMPLETE" else "")
            for o in obligations if o.verification]
