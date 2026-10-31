"""Evaluate supplied rule conditions with three-valued evidence predicates."""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from .contracts import Fact, Issue, Resource, timestamp
from .identity import Subject, identifier
from .risks import flow_enabled, restore_enabled
from .timeline import State

CONDITIONS = {
    "Always", "Conversation contains shared customer, agent, or order context that must be retained",
    "Attachment belongs only to the deletion subject", "Record is still attributable to a user",
    "Log contains a user email address", "Record is within the supplied retention period",
    "A supplied legal hold is active", "Restore access can be blocked",
    "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
}
DIRECT = frozenset({"name", "email", "phone", "email_hash"})
TARGETS = {"DELETE": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD"),
           "REDACT": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REPORT_EXPOSED_PII"),
           "ANONYMIZE": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", "REPORT_EXPOSED_PII"),
           "RETAIN": ("", "VERIFY_RECORD_PRESENT", "")}


@dataclass
class Obligation:
    resource: Resource
    category: str
    rule_id: str = ""
    action: str = ""
    verification: str = ""
    finding: str = ""
    remediation: str = ""
    compliant: bool | None = None
    proof: list[Fact] = field(default_factory=list)
    violation_proof: list[Fact] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


def has_identifiers(f: Fact, subject: Subject, *, anonymous=False) -> bool:
    keys = DIRECT | ({"user_id"} if anonymous else set())
    for key in keys:
        field_owner = f.fields.get("field_subjects", {}).get(key)
        if field_owner and field_owner != subject.user_id: continue
        value = f.fields.get(key)
        if value not in (None, "", "[REDACTED]", "REDACTED"):
            return True
    if f.fields.get("detected_identifier") or f.fields.get("result") == "IDENTIFIABLE": return True
    if isinstance(f.fields.get("direct_identifiers"), int) and f.fields["direct_identifiers"] > 0: return True
    text = f.fields.get("text", "")
    folded = str(text).casefold()
    aliases = subject.aliases | subject.names
    if not anonymous: aliases = {a for a in aliases if not a.startswith("user_")}
    return any(a.casefold() in folded for a in aliases if len(a) > 3)


def cleaned(f: Fact, subject: Subject, anonymous=False) -> bool | None:
    if has_identifiers(f, subject, anonymous=anonymous): return False
    if f.state == ("ANONYMIZED" if anonymous else "REDACTED"): return True
    needed = DIRECT | {"user_id"} if anonymous else DIRECT
    if needed <= f.coverage: return True
    # A redacted message read is explicit content evidence; a generic scanner
    # saying direct_identifiers=0 does not prove all stable links were removed.
    if not anonymous and f.fields.get("text") == "[REDACTED]": return True
    return None


class Policy:
    def __init__(self, rows: list[dict]):
        self.rules = {}
        for row in rows:
            if set(row) != {"rule_id", "data_category", "condition", "required_action"}: raise ValueError("Invalid policy schema")
            if row["condition"] not in CONDITIONS or row["required_action"] not in TARGETS:
                raise ValueError("Unsupported policy condition/action: " + row["rule_id"])
            self.rules.setdefault(row["data_category"], []).append(row)

    def evaluate(self, state: State, subject: Subject, cutoff, context: list[Fact]) -> Obligation:
        out = Obligation(state.resource, state.category)
        out.issues.extend(state.issues)
        observations = state.observations
        if not observations or not state.category: return out
        context = [f for f in context if f.resource == state.resource and f.admitted(cutoff)]
        if state.category == "DATA_FLOW":
            out.rule_id = "contract:active_data_flow"
            out.action, out.remediation, out.verification, out.finding = "DISABLE", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", "REPORT_ACTIVE_DATA_FLOW"
            values = [flow_enabled(f) for f in observations]
            self._conclude(out, observations, [None if v is None else not v for v in values])
            return out
        rules = self.rules.get(state.category, [])
        if len(rules) != 1:
            out.issues.append(Issue("POLICY_RULE_UNRESOLVED", "policy", "Expected one supported rule for the grounded category.", state.resource.resource_id))
            return out
        rule = rules[0]
        out.rule_id, out.action = rule["rule_id"], rule["required_action"]
        out.remediation, out.verification, out.finding = TARGETS[out.action]
        condition = rule["condition"]
        if state.category == "BACKUP_ARCHIVE":
            out.verification, out.remediation, out.finding = "VERIFY_RESTORE_BLOCKED", "BLOCK_RESTORE", "REPORT_RESTORE_RISK"
            if any(f.state == "ABSENT" or f.fields.get("archive_present") is False for f in observations):
                out.issues.append(Issue("RETAINED_RECORD_MISSING", "policy", "Required backup is absent; no allowed recovery operation exists.", state.resource.resource_id))
                return out
            self._conclude(out, observations, [None if restore_enabled(f) is None else not restore_enabled(f) for f in observations])
            return out
        if condition == "Attachment belongs only to the deletion subject":
            exclusive = any(f.fields.get("exclusive_subject") is True or (f.kind == "LINK" and "belongs only" in f.fields.get("details", "").lower()) for f in context)
            if not exclusive:
                out.issues.append(Issue("EXCLUSIVE_OWNERSHIP_UNPROVEN", "policy", "Attachment category is known, but exclusive subject ownership is not established.", state.resource.resource_id, tuple(sorted({f.evidence_id for f in context}))))
        if condition.startswith("Conversation contains"):
            shared = any(f.fields.get("shared_context") is True or f.fields.get("ticket_id") or f.fields.get("channel") or f.fields.get("event") in {"message_read", "message_pii_scan", "support_ticket_read_completed"} or re.search(r"\b(?:customer|agent|order|conversation|support)\b", str(f.fields.get("text", "")), re.I) for f in context)
            if not shared:
                # Redaction removes only the deletion subject's identifiers and
                # preserves the conversation. Explicitly attributed exposure
                # supports that safe action even when the reason to preserve
                # shared context is not documented. This never licenses whole-
                # record deletion or establishes COMPLETE policy compliance.
                exposed=[f for f in observations if has_identifiers(f,subject)]
                scoped=bool(exposed) and all(any(identifier(v) in subject.aliases for v in f.links) for f in exposed)
                out.issues.append(Issue("SHARED_CONTEXT_UNPROVEN", "policy", "Shared-context preservation condition is unproven; only explicitly attributed subject redaction may proceed, preserving all other context.", state.resource.resource_id,
                                        effect="COMPLETE" if scoped else "PUBLIC"))
        if out.action == "RETAIN":
            # Instruments are assertions with their own observation times. A
            # newer amendment can shorten a period; taking the historical max
            # silently reinstates an expired/revoked obligation.
            instruments=[f for f in context if "retention_until" in f.fields or "retention_required" in f.fields]
            if instruments:
                newest=max(f.observed for f in instruments)
                instruments=[f for f in instruments if f.observed == newest]
            periods = []
            invalid_period=False
            for f in instruments:
                value = f.fields.get("retention_until")
                if value:
                    try: periods.append(timestamp(value))
                    except (ValueError, TypeError): invalid_period=True
            explicit = any(f.fields.get("retention_required") is True for f in instruments)
            if invalid_period:
                out.issues.append(Issue("INVALID_RETENTION_PERIOD", "policy", "Supplied retention time cannot be parsed without an assumption.", state.resource.resource_id))
            if len(set(periods)) > 1 or len({f.fields['retention_required'] for f in instruments if type(f.fields.get('retention_required')) is bool}) > 1:
                out.issues.append(Issue("RETENTION_INSTRUMENT_CONFLICT", "policy", "Latest retention instruments disagree.", state.resource.resource_id))
            if any(f.fields.get("retention_required") is False for f in instruments):
                out.issues.append(Issue("INACTIVE_RETENTION_UNSPECIFIED", "policy", "Retention obligation was released; alternative treatment is not supplied.", state.resource.resource_id))
            hold_facts=[f for f in context if type(f.fields.get("hold_active")) is bool]
            if hold_facts:
                latest_time=max(f.observed for f in hold_facts)
                values={f.fields["hold_active"] for f in hold_facts if f.observed==latest_time}
                if len(values)>1:
                    out.issues.append(Issue("LEGAL_HOLD_CONFLICT", "policy", "Latest legal-hold instruments disagree.", state.resource.resource_id))
                elif values=={False}:
                    out.issues.append(Issue("INACTIVE_HOLD_UNSPECIFIED", "policy", "Legal hold was released; alternative treatment is not supplied.", state.resource.resource_id))
                else:explicit=True
            if not periods and not explicit:
                out.issues.append(Issue("RETENTION_CONDITION_UNKNOWN", "policy", "Active retention obligation is unproven. Preserve the observed record; its presence check is safe in an independently INCOMPLETE plan, but does not prove policy compliance.", state.resource.resource_id, tuple(sorted({f.evidence_id for f in context})), investigation="Find an applicable pre-cutoff retention instrument; do not invent a duration.", effect="COMPLETE"))
            elif periods and max(periods) <= cutoff and not explicit:
                out.issues.append(Issue("EXPIRED_RETENTION_UNSPECIFIED", "policy", "Retention expired; no alternative treatment is supplied.", state.resource.resource_id))
            if any(f.state == "ABSENT" for f in observations):
                out.issues.append(Issue("RETAINED_RECORD_MISSING", "policy", "Required retained record is absent; recovery is outside allowed operations.", state.resource.resource_id))
            out.compliant = True if not out.issues else None
            out.proof = observations
        elif out.action == "DELETE":
            self._conclude(out, observations, [f.state == "ABSENT" for f in observations])
        else:
            if any(f.state == "ABSENT" for f in observations):
                out.issues.append(Issue("REQUIRED_CONTENT_MISSING", "policy", "Record required for redaction/anonymization is absent; no recovery action is specified.", state.resource.resource_id))
            if state.category == "ACCOUNT_TOMBSTONE":
                if not all(f.fields.get("user_id") == subject.user_id and f.fields.get("account_status") == "DELETED" for f in observations):
                    out.issues.append(Issue("TOMBSTONE_REFERENCE_UNPROVEN", "policy", "Deleted status and permitted stable reference must be preserved.", state.resource.resource_id))
            if state.category == "EMAIL_DELIVERY_LOG":
                values=[]
                emails={a.casefold() for a in subject.aliases if "@" in a}
                for f in observations:
                    exposed=(isinstance(f.fields.get("email"),str) and f.fields["email"].casefold() in emails) or any(e in str(f.fields.get("text","")).casefold() for e in emails)
                    values.append(False if exposed else True if f.state=="REDACTED" or "email" in f.coverage or "text" in f.coverage else None)
                self._conclude(out,observations,values)
            else:
                self._conclude(out, observations, [cleaned(f, subject, out.action == "ANONYMIZE") for f in observations])
        return out

    @staticmethod
    def _conclude(out, observations, values):
        out.violation_proof = [f for f, v in zip(observations, values) if v is False]
        out.proof = list(observations)
        out.compliant = False if False in values else None if None in values else True
        if None in values:
            out.issues.append(Issue("STATE_FIELDS_INSUFFICIENT", "policy", "Observation lacks fields required to prove the target state.", out.resource.resource_id, tuple(sorted({f.evidence_id for f, v in zip(observations, values) if v is None}))))
