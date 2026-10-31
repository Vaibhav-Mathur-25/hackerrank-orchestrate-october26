"""Historical bindings and conservative resource attribution; names never merge people."""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from .contracts import Fact, Issue, Resource, timestamp


def identifier(value: str) -> str:
    value = value.strip()
    if "@" in value: return value.casefold()
    if value.startswith("+"): return "+" + re.sub(r"\D", "", value)
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return value.lower()
    return value


@dataclass(frozen=True)
class Binding:
    subject: str
    field: str
    value: str
    available: object
    start: object | None = None
    end: object | None = None
    evidence_id: str = ""


@dataclass
class Subject:
    user_id: str = ""
    aliases: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    resources: set[Resource] = field(default_factory=set)
    issues: list[Issue] = field(default_factory=list)


def pre_request_negative_probe(resource, subject, facts, request_start, cutoff):
    """A historical lookup miss alone does not establish current ownership.

    Keep real membership/existence evidence regardless of age. Keep current
    request probes and any possible recreation; this only removes a weak
    negative-only account association from a later request's inventory.
    """
    if request_start is None or any(i.resource_id==resource.resource_id for i in subject.issues):return False
    for f in facts:
        if not f.admitted(cutoff):continue
        if f.fields.get('source_resource_id')==resource.resource_id and f.fields.get('source_system')==resource.system:return False
        if any(isinstance(d,dict) and d.get('system_id')==resource.system and d.get('resource_id')==resource.resource_id
               for d in f.fields.get('downstream_resources',[])):return False
    relevant=[f for f in facts if f.resource==resource and f.admitted(cutoff)]
    linked=[f for f in relevant if any(identifier(v) in subject.aliases for v in f.links)]
    if not linked:return False
    for f in linked:
        if f.kind!='OBSERVATION' or f.category!='USER_PROFILE' or f.state!='ABSENT' or f.observed>=request_start:return False
        if any(f.fields.get(k) not in (None,'') for k in ['user_id','email','phone','email_hash']):return False
    for f in relevant:
        if f.kind=='LINK' or (f.kind=='OBSERVATION' and f.state!='ABSENT'):return False
        if f.kind=='CLAIM' and (f.links or f.fields.get('event_type') in {'CREATE_RECORD','UPDATE_RECORD','SYNC_RECORD','RESTORE_BACKUP'}):return False
    return True


class IdentityGraph:
    def __init__(self, identities: list[dict], audits: list[dict]):
        self.identities = identities
        self.audits = audits
        self.subjects = {r["user_id"] for r in identities} | {r["user_id"] for r in audits}

    def bindings(self, cutoff):
        bindings = []
        issues = []
        for row in self.identities:
            when = timestamp(row["updated_at"])
            if when > cutoff: continue
            for key in ["email", "phone", "email_hash"]:
                if row.get(key): bindings.append(Binding(row["user_id"], key, identifier(row[key]), when, when))
        chains = {}
        for row in self.audits:
            if timestamp(row["event_time"]) <= cutoff:
                chains.setdefault((row["user_id"], row["field_name"]), []).append(row)
        for (uid, key), chain in chains.items():
            chain.sort(key=lambda r: (r["event_time"], r["audit_id"]))
            for i, row in enumerate(chain):
                when = timestamp(row["event_time"])
                if i and identifier(chain[i-1]["new_value"]) != identifier(row["old_value"]):
                    issues.append((uid, Issue("IDENTITY_CHAIN_CONFLICT", "identity", "Historical identifier transition is inconsistent.", evidence_ids=(chain[i-1]["audit_id"], row["audit_id"]))))
                start = timestamp(chain[i-1]["event_time"]) if i else None
                bindings.append(Binding(uid, key, identifier(row["old_value"]), when, start, when, row["audit_id"]))
                end = timestamp(chain[i+1]["event_time"]) if i+1 < len(chain) else None
                bindings.append(Binding(uid, key, identifier(row["new_value"]), when, when, end, row["audit_id"]))
        return bindings, issues

    def resolve(self, email: str, cutoff, facts: list[Fact], *, request_start=None) -> Subject:
        bindings, binding_issues = self.bindings(cutoff)
        owners = {}
        for b in bindings: owners.setdefault(b.value, set()).add(b.subject)
        # Stable IDs are identities, but resource membership still needs a supplied link.
        for uid in self.subjects: owners.setdefault(uid, set()).add(uid)
        candidates = owners.get(identifier(email), set())
        subject = Subject()
        if len(candidates) != 1:
            subject.issues.append(Issue("SUBJECT_UNRESOLVED", "identity", "Request email has zero or multiple admissible subject matches.", investigation="Find a pre-cutoff identity binding disambiguating the request email."))
            return subject
        subject.user_id = next(iter(candidates))
        subject.aliases = {b.value for b in bindings if b.subject == subject.user_id} | {subject.user_id}
        subject.names = {r["name"] for r in self.identities if r["user_id"] == subject.user_id and timestamp(r["updated_at"]) <= cutoff}
        subject.issues.extend(issue for uid, issue in binding_issues if uid == subject.user_id)
        for fact in facts:
            if not fact.resource.resource_id or not fact.admitted(cutoff): continue
            linked_owners = set()
            for value in fact.links: linked_owners.update(owners.get(identifier(value), set()))
            if subject.user_id not in linked_owners: continue
            explicit_shared = fact.fields.get("shared_subjects", [])
            if len(linked_owners) > 1 and not linked_owners.issubset(set(explicit_shared)):
                subject.issues.append(Issue("IDENTITY_CONFLICT", "identity", "A resource observation links multiple incompatible subjects without explicit shared membership.", fact.resource.resource_id, (fact.evidence_id,)))
            subject.resources.add(fact.resource)
        subject.resources={r for r in subject.resources if not pre_request_negative_probe(r,subject,facts,request_start,cutoff)}
        # Compare ownership across assertions; a new catalog claim does not erase
        # another customer's observed identifiers or prove reassignment.
        for resource in sorted(subject.resources):
            linked = [f for f in facts if f.resource == resource and f.admitted(cutoff)]
            other = set()
            explicit = set()
            for fact in linked:
                explicit.update(fact.fields.get("shared_subjects", []))
                for value in fact.links: other.update(owners.get(identifier(value), set()))
            if len(other) > 1 and not other.issubset(explicit):
                subject.issues.append(Issue("RESOURCE_OWNERSHIP_CONFLICT", "identity", "Admissible resource links disagree about ownership; no explicit reassignment is supplied.", resource.resource_id, tuple(sorted({f.evidence_id for f in linked}))))
            for fact in linked:
                if fact.kind != "OBSERVATION": continue
                field_owners = fact.fields.get("field_subjects", {})
                for key in ["email", "phone", "email_hash", "user_id"]:
                    value = fact.fields.get(key)
                    if value in (None,"","[REDACTED]","REDACTED") or not isinstance(value,str): continue
                    if key in field_owners and field_owners[key] != subject.user_id: continue
                    if identifier(value) not in subject.aliases:
                        subject.issues.append(Issue("RESOURCE_IDENTIFIER_CONFLICT", "identity", "Stored identifier is not among the subject's admissible current/historical bindings; ownership needs review.", resource.resource_id, (fact.evidence_id,)))
                        break
        return subject
