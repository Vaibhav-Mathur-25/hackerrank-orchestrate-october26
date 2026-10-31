"""Independent public-contract and provenance validators."""
from __future__ import annotations

from .contracts import Assessment, PHASES, STATUSES, STEP_FIELDS, step_key


def supports_operation(fact, operation, subject):
    """Check the assertion itself, independently of the proof-ledger key."""
    from .policy import cleaned, has_identifiers
    from .risks import flow_enabled, restore_enabled
    if operation == "VERIFY_RECORD_ABSENT": return fact.state == "ABSENT"
    if operation in {"VERIFY_RECORD_PRESENT", "REPORT_REMAINING_RECORD"}:
        return fact.state in {"PRESENT", "REDACTED", "ANONYMIZED"}
    if operation == "REPORT_ACTIVE_DATA_FLOW": return flow_enabled(fact) is True
    if operation == "VERIFY_DATA_FLOW_DISABLED": return flow_enabled(fact) is False
    if operation == "REPORT_RESTORE_RISK": return restore_enabled(fact) is True
    if operation == "VERIFY_RESTORE_BLOCKED": return restore_enabled(fact) is False
    if operation == "REPORT_EXPOSED_PII":
        if fact.state == "ABSENT": return False
        if fact.category == "EMAIL_DELIVERY_LOG":
            emails={a.casefold() for a in subject.aliases if "@" in a}
            return str(fact.fields.get("email", "")).casefold() in emails or any(e in str(fact.fields.get("text", "")).casefold() for e in emails)
        return has_identifiers(fact, subject, anonymous=fact.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"})
    if operation in {"VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED"}:
        if fact.state == "ABSENT": return False
        if fact.category == "EMAIL_DELIVERY_LOG":
            return not supports_operation(fact,"REPORT_EXPOSED_PII",subject) and (fact.state == "REDACTED" or bool({"email","text"} & fact.coverage))
        if fact.category == "ACCOUNT_TOMBSTONE" and not (fact.fields.get("user_id") == subject.user_id and fact.fields.get("account_status") == "DELETED"):
            return False
        return cleaned(fact,subject,operation == "VERIFY_RECORD_ANONYMIZED") is True
    return False


def validate_steps(status: str, steps: list[dict]) -> None:
    if status not in STATUSES or not isinstance(steps, list):
        raise ValueError("Invalid status/steps")
    if status == "NOT_APPLICABLE" and steps:
        raise ValueError("Non-deletion requests cannot have steps")
    if status != "NOT_APPLICABLE" and not steps:
        raise ValueError("Deletion decisions require grounded verification")
    seen = set()
    for n, step in enumerate(steps, 1):
        if not isinstance(step, dict) or set(step) != STEP_FIELDS:
            raise ValueError("Step must contain exactly seven contract fields")
        if type(step["step_no"]) is not int or step["step_no"] != n:
            raise ValueError("Nonconsecutive integer step numbering")
        if any(not isinstance(step[k], str) for k in STEP_FIELDS - {"step_no"}):
            raise ValueError("Step fields must be strings")
        phase, operation = step["phase"], step["operation"]
        if phase not in PHASES or PHASES[phase].get(operation) != step["state"]:
            raise ValueError("Invalid phase/operation/state combination")
        if not step["system_id"] or not step["resource_id"]:
            raise ValueError("Missing resource identity")
        if status == "COMPLETE" and phase != "VERIFICATION":
            raise ValueError("Complete cases have verification only")
        future = phase == "REMEDIATION" or (status == "INCOMPLETE" and phase == "VERIFICATION")
        if future == bool(step["evidence_id"]):
            raise ValueError("Incorrect evidence reference for phase/status")
        signature = tuple(step[k] for k in sorted(STEP_FIELDS - {"step_no"}))
        if signature in seen:
            raise ValueError("Duplicate step")
        seen.add(signature)
    if steps != sorted(steps, key=step_key):
        raise ValueError("Noncanonical step ordering")
    if status == "INCOMPLETE" and not all(any(s["phase"] == p for s in steps) for p in PHASES):
        raise ValueError("Incomplete case needs findings, remediation and verification")


def validate_assessment(result: Assessment, cutoff) -> None:
    if not result.resolved:
        raise ValueError("Cannot serialize unresolved case")
    validate_steps(result.status, result.steps)
    from .discovery import validate_coverage
    validate_coverage(result.discovery,result.steps,result.status)
    checks = {(s["system_id"], s["resource_id"], s["operation"]) for s in result.steps if s["phase"] == "VERIFICATION"}
    expected = {(r["system_id"], r["resource_id"], r["verification"]) for r in result.inventory}
    if checks != expected:
        raise ValueError("Verification inventory mismatch")
    resources = {(r["system_id"], r["resource_id"]) for r in result.inventory}
    inventory = {(r["system_id"], r["resource_id"]):r for r in result.inventory}
    from .identity import Subject
    from .policy import TARGETS
    subject=Subject(user_id=result.subject_id,aliases=result.subject_aliases,names=result.subject_names)
    if result.status == "COMPLETE" and any(r["compliant"] is not True for r in result.inventory):
        raise ValueError("Complete assessment contains unproven obligations")
    expected_actions=set()
    for record in result.inventory:
        targets=TARGETS.get(record.get("action"))
        if record.get("category") == "DATA_FLOW": targets=("DISABLE_DATA_FLOW","VERIFY_DATA_FLOW_DISABLED","REPORT_ACTIVE_DATA_FLOW")
        if record.get("category") == "BACKUP_ARCHIVE": targets=("BLOCK_RESTORE","VERIFY_RESTORE_BLOCKED","REPORT_RESTORE_RISK")
        if record.get("compliant") is False and targets:
            expected_actions.update((phase,record['system_id'],record['resource_id'],operation)
                                    for phase,operation in [('FINDING',targets[2]),('REMEDIATION',targets[0])])
    actual_actions={(s['phase'],s['system_id'],s['resource_id'],s['operation']) for s in result.steps if s['phase'] != 'VERIFICATION'}
    if expected_actions != actual_actions:
        raise ValueError("Incomplete policy action/finding coverage")
    for step in result.steps:
        if (step["system_id"], step["resource_id"]) not in resources:
            raise ValueError("Unsupported resource")
        if step["evidence_id"]:
            key = (step["system_id"], step["resource_id"], step["operation"])
            support = result.proofs.get(key, [])
            if not any(f.evidence_id == step["evidence_id"] and f.kind == "OBSERVATION" and f.resource.system == step["system_id"] and f.resource.resource_id == step["resource_id"] and f.admitted(cutoff) and not f.fields.get("extraction_uncertain") and supports_operation(f,step["operation"],subject) for f in support):
                raise ValueError("Missing admissible semantic proof")
            if result.status == 'COMPLETE' and not all(f.kind=='OBSERVATION' and f.admitted(cutoff) and supports_operation(f,step['operation'],subject) for f in support):
                raise ValueError("Complete verification contradicts another store's proof")
        if step["phase"] in {"FINDING", "REMEDIATION"}:
            record=inventory[(step["system_id"],step["resource_id"])]
            targets=TARGETS.get(record.get("action"))
            if record.get("category") == "DATA_FLOW": targets=("DISABLE_DATA_FLOW","VERIFY_DATA_FLOW_DISABLED","REPORT_ACTIVE_DATA_FLOW")
            if record.get("category") == "BACKUP_ARCHIVE": targets=("BLOCK_RESTORE","VERIFY_RESTORE_BLOCKED","REPORT_RESTORE_RISK")
            expected_op=targets[2 if step["phase"] == "FINDING" else 0] if targets else None
            if record.get("compliant") is not False or step["operation"] != expected_op:
                raise ValueError("Unsupported policy action or finding")
