"""Observed configuration, not last operation result, determines process risk."""
from .contracts import Fact


def flow_enabled(fact: Fact) -> bool | None:
    if type(fact.fields.get("enabled")) is bool: return fact.fields["enabled"]
    return {"ACTIVE": True, "DISABLED": False}.get(fact.state)


def restore_enabled(fact: Fact) -> bool | None:
    if type(fact.fields.get("restore_allowed")) is bool: return fact.fields["restore_allowed"]
    return {"ACTIVE": True, "BLOCKED": False}.get(fact.state)
