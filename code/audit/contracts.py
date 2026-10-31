"""Shared contracts. Internal uncertainty never becomes a public output enum."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

PHASES = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}
STEP_FIELDS = frozenset({"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"})
STATUSES = frozenset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})


def timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True, order=True)
class Resource:
    system: str
    resource_id: str


@dataclass(frozen=True)
class Fact:
    evidence_id: str
    locator: str
    observed: datetime
    available: datetime
    resource: Resource
    category: str = ""
    kind: str = "OBSERVATION"
    store: str = "logical"
    fields: dict[str, Any] = field(default_factory=dict)
    links: tuple[str, ...] = ()
    state: str = ""
    coverage: frozenset[str] = frozenset()

    def admitted(self, cutoff: datetime) -> bool:
        return self.available <= cutoff and self.observed <= cutoff and self.observed <= self.available


@dataclass(frozen=True)
class Issue:
    code: str
    component: str
    message: str
    resource_id: str = ""
    evidence_ids: tuple[str, ...] = ()
    blocking: bool = True
    investigation: str = "Inspect the cited participant evidence and resolve the missing fact."
    effect: str = "PUBLIC"

    def prevents(self, status):
        if self.effect not in {"PUBLIC", "COMPLETE", "ADVISORY"}:
            raise ValueError("Unknown issue effect")
        return self.blocking and self.effect != "ADVISORY" and (self.effect != "COMPLETE" or status == "COMPLETE")


@dataclass(frozen=True)
class Request:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str

    @classmethod
    def from_row(cls, row: dict[str, str]) -> Request:
        required = {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}
        if set(row) != required or any(v is None for v in row.values()):
            raise ValueError("Invalid request columns")
        if not row["case_id"] or row["reported_status"] not in {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}:
            raise ValueError("Invalid request identity/status")
        return cls(**{k: timestamp(v) if k.endswith("_at") else v for k, v in row.items()})


@dataclass
class Assessment:
    case_id: str
    status: str | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    proofs: dict[tuple[str, str, str], list[Fact]] = field(default_factory=dict)
    subject_id: str = ""
    subject_aliases: set[str] = field(default_factory=set)
    subject_names: set[str] = field(default_factory=set)
    discovery: dict[str, Any] = field(default_factory=dict)
    verification_ledger: list[dict[str, Any]] = field(default_factory=list)
    relationship_proofs: list[Fact] = field(default_factory=list)

    @property
    def gates(self):
        return {"verdict_supported": self.status in STATUSES,
                "actions_supported": not any(i.prevents(self.status) and i.component in {"identity","policy","timeline","planner"} for i in self.issues),
                "verification_covered": not any(i.prevents(self.status) and i.component == "coverage" for i in self.issues),
                "complete_evidence": not any(i.blocking and i.effect != "ADVISORY" for i in self.issues)}

    @property
    def resolved(self) -> bool:
        return self.status in STATUSES and not any(i.prevents(self.status) for i in self.issues)


def step_key(step: dict[str, Any]) -> tuple:
    phase = step["phase"]
    return (list(PHASES).index(phase), list(PHASES[phase]).index(step["operation"]), step["system_id"], step["resource_id"])


def make_step(phase: str, operation: str, resource: Resource, evidence_id: str = "") -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": resource.system,
            "resource_id": resource.resource_id, "operation": operation,
            "state": PHASES[phase][operation], "evidence_id": evidence_id}


def order_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(step, step_no=n) for n, step in enumerate(sorted(steps, key=step_key), 1)]
