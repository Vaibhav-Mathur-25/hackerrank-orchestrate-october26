"""As-of reconstruction without promoting operation claims to proven state."""
from __future__ import annotations
from dataclasses import dataclass, field
from dataclasses import replace
from .contracts import Fact, Issue, Resource


@dataclass
class State:
    resource: Resource
    category: str
    observations: list[Fact] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


def reconstruct(resource: Resource, facts: list[Fact], cutoff, category: str = "") -> State:
    relevant = [f for f in facts if f.resource == resource and f.admitted(cutoff)]
    categories = {f.category for f in relevant if f.category and f.kind != "CLAIM"}
    if category: categories.add(category)
    out = State(resource, next(iter(categories)) if len(categories) == 1 else "")
    if len(categories) != 1:
        out.issues.append(Issue("CATEGORY_UNKNOWN" if not categories else "CATEGORY_CONFLICT", "timeline", "Resource category is missing or contradictory.", resource.resource_id, tuple(sorted({f.evidence_id for f in relevant}))))
    # Only an explicit physical target can collapse a logical readback onto a
    # SQL store. Never assume an unspecified readback covers every replica.
    observations = [replace(f,store=f.fields.get('physical_store',f.store)) for f in relevant if f.kind == "OBSERVATION"]
    stores = {f.store for f in observations}
    direct_stores=set(stores)
    scopes = [f for f in facts if f.kind == "SCOPE" and f.admitted(cutoff) and f.resource.system == resource.system and f.category == out.category and f.fields.get("complete")]
    # A complete snapshot can prove absence only for a previously grounded resource.
    for scope in scopes:
        # An empty table is not evidence of a missing required retained copy in
        # a store where this resource has never been observed. When no direct
        # readback exists, a grounded foreign key can be checked against the
        # declared stores of a full export (e.g. account primary + failover).
        if direct_stores and scope.store not in direct_stores:
            continue
        if resource.resource_id not in scope.fields["members"]:
            observations.append(Fact(scope.evidence_id, scope.locator, scope.observed, scope.available, resource,
                                     out.category, "OBSERVATION", scope.store, {}, (), "ABSENT"))
            stores.add(scope.store)
    for store in sorted(stores):
        values = [f for f in observations if f.store == store]
        latest_time = max(f.observed for f in values)
        latest = [f for f in values if f.observed == latest_time]
        corroborated={(f.evidence_id,f.locator,f.state) for f in latest if f.fields.get('ocr_corroboration')}
        latest=[f for f in latest if not(f.fields.get('extraction_uncertain') and (f.evidence_id,f.locator,f.state) in corroborated)]
        states = {f.state for f in latest}
        contradiction = len(states) > 1
        for i, left in enumerate(latest):
            for right in latest[i + 1:]:
                state_fields={'user_id','name','email','phone','email_hash','text','enabled','restore_allowed','account_status','direct_identifiers','detected_identifier','archive_present'}
                contradiction |= any(left.fields[k] != right.fields[k] for k in left.coverage & right.coverage & state_fields)
        if contradiction:
            out.issues.append(Issue("STATE_CONFLICT", "timeline", "Equally timed observations disagree in the same store.", resource.resource_id, tuple(sorted({f.evidence_id for f in latest}))))
        out.observations.extend(latest)
        if any(f.fields.get("extraction_uncertain") for f in latest):
            out.issues.append(Issue("EXTRACTION_UNVERIFIED", "timeline", "Critical OCR identifier lacks sufficient extraction confidence.", resource.resource_id, tuple(sorted({f.evidence_id for f in latest})), investigation="Visually verify the original image; do not silently repair the OCR value."))
    if not out.observations:
        out.issues.append(Issue("NO_STATE_OBSERVATION", "timeline", "Only relationship/operation claims exist; no admissible state proof.", resource.resource_id, tuple(sorted({f.evidence_id for f in relevant}))))
    if out.observations:
        last = max(f.observed for f in out.observations)
        for claim in relevant:
            if claim.kind == "CLAIM" and claim.observed > last and claim.fields.get("event_type") in {"SYNC_RECORD", "RESTORE_BACKUP", "UPDATE_RECORD", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"}:
                event=claim.fields.get('event_type')
                # Idempotent/non-creating treatment cannot recreate a resource
                # already proven absent. This preserves that observation; the
                # claim is never promoted to a new state proof.
                if event in {'DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD'} and all(f.state=='ABSENT' for f in out.observations):
                    continue
                if event=='DISABLE_DATA_FLOW' and all(f.state=='DISABLED' or f.fields.get('enabled') is False for f in out.observations):continue
                if event=='BLOCK_RESTORE' and all(f.state=='BLOCKED' or f.fields.get('restore_allowed') is False for f in out.observations):continue
                out.issues.append(Issue("UNVERIFIED_TRANSITION", "timeline", "A later state-changing operation lacks a resulting observation.", resource.resource_id, (claim.evidence_id,)))
    return out
