"""Case orchestration; only fully resolved assessments can become public rows."""
from __future__ import annotations
from .contracts import Assessment, Issue, make_step, order_steps, timestamp
from .identity import IdentityGraph, identifier
from .intent import classify
from .timeline import reconstruct
from .policy import Policy
from .citations import choose
from .verification import verification_steps, build_ledger
from .validate import validate_assessment
from .discovery import assess


class Auditor:
    def __init__(self, dataset):
        self.dataset = dataset
        self.identity = IdentityGraph(dataset.identities, dataset.audits)
        self.policy = Policy(dataset.rules)

    def audit(self, request):
        result = Assessment(request.case_id)
        intent = classify(request.request_text)
        if intent.authorized is False:
            result.status = "NOT_APPLICABLE"
            return result
        if intent.authorized is None:
            result.issues.append(Issue("INTENT_UNRESOLVED", "intent", intent.reason))
            return result
        subject = self.identity.resolve(request.email, request.audit_at, self.dataset.facts,request_start=request.requested_at)
        result.subject_id = subject.user_id
        result.subject_aliases = subject.aliases
        result.subject_names = subject.names
        result.issues.extend(subject.issues)
        if not subject.user_id: return result
        result.relationship_proofs=[f for f in self.dataset.facts if f.kind=='LINK' and f.admitted(request.audit_at)
                                    and any(identifier(v) in subject.aliases for v in f.links)]
        result.discovery, coverage_issues = assess(subject,request,self.dataset.facts)
        result.issues.extend(coverage_issues)
        availability={a["file_id"]:timestamp(a["captured_at"]) for a in self.dataset.artifacts}
        result.issues.extend(i for i in self.dataset.issues if i.blocking and
                             (not i.evidence_ids or any(availability.get(e,request.audit_at)<=request.audit_at for e in i.evidence_ids)))
        obligations = []
        for resource in sorted(subject.resources):
            state = reconstruct(resource, self.dataset.facts, request.audit_at)
            obligation = self.policy.evaluate(state, subject, request.audit_at, self.dataset.facts)
            obligations.append(obligation)
            result.issues.extend(obligation.issues)
            if obligation.verification:
                result.inventory.append({"system_id": resource.system, "resource_id": resource.resource_id,
                                         "category": obligation.category, "rule_id": obligation.rule_id,
                                         "action": obligation.action,
                                         "verification": obligation.verification, "compliant": obligation.compliant})
        result.verification_ledger=build_ledger(obligations,subject,request.audit_at)
        violations = [o for o in obligations if o.compliant is False and o.finding and o.remediation]
        # A remaining record proves a violation only when attribution and the
        # applicable treatment condition are established. An unrelated global
        # coverage gap still cannot erase an independently supported violation.
        established = [o for o in violations if not any(
            i.blocking and i.resource_id == o.resource.resource_id and
            (i.component == 'identity' or i.code == 'EXCLUSIVE_OWNERSHIP_UNPROVEN')
            for i in result.issues)]
        if established: result.status = "INCOMPLETE"
        elif obligations and not any(i.blocking for i in result.issues) and all(o.compliant is True for o in obligations):
            result.status = "COMPLETE"
        elif not obligations:
            result.issues.append(Issue("NO_RESOURCE_INVENTORY", "identity", "No grounded resource inventory is available."))
        steps = []
        for o in violations:
            steps.append(make_step("FINDING", o.finding, o.resource, choose(o.violation_proof, request.audit_at)))
            result.proofs[(o.resource.system, o.resource.resource_id, o.finding)] = o.violation_proof
            steps.append(make_step("REMEDIATION", o.remediation, o.resource))
        if result.status:
            steps.extend(verification_steps(obligations, result.status, request.audit_at))
        for o in obligations:
            result.proofs[(o.resource.system, o.resource.resource_id, o.verification)] = o.proof
            if o.category=='BACKUP_ARCHIVE':
                # Presence and restore authorization are distinct predicates.
                # Keeping this readback does not establish restore safety.
                result.proofs[(o.resource.system,o.resource.resource_id,'VERIFY_RECORD_PRESENT')]=o.proof
        result.steps = order_steps(steps)
        self._dependencies(result, request)
        if result.resolved: validate_assessment(result, request.audit_at)
        return result

    def _dependencies(self, result, request):
        positions = {(s["system_id"], s["resource_id"]): n for n, s in enumerate(result.steps) if s["phase"] == "REMEDIATION"}
        operations = {(s["system_id"],s["resource_id"]):s["operation"] for s in result.steps if s["phase"]=="REMEDIATION"}
        for fact in self.dataset.facts:
            if not fact.admitted(request.audit_at): continue
            for downstream in fact.fields.get("downstream_resources", []):
                parent = (fact.resource.system, fact.resource.resource_id)
                child = (downstream["system_id"], downstream["resource_id"])
                if operations.get(parent)==operations.get(child)=="DELETE_RECORD" and positions[parent] < positions[child]:
                    result.issues.append(Issue("ORDER_CONTRACT_CONFLICT", "planner", "Explicit downstream-first dependency contradicts canonical output order.", fact.resource.resource_id, (fact.evidence_id,)))
