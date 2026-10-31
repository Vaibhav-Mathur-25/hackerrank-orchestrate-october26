from __future__ import annotations
import json
import re
from ..contracts import Fact, Resource, timestamp
from ..normalize import CATEGORIES, record_fact, tokens


def scope_fact(eid, locator, available, observed, system, category, store, members, complete=False):
    return Fact(eid, locator, timestamp(observed), timestamp(available), Resource(system, ""), category,
                "SCOPE", store, {"members": tuple(sorted(members)), "complete": complete}, state="")


def json_facts(data: bytes, eid: str, captured: str) -> list[Fact]:
    doc = json.loads(data)
    if not isinstance(doc, dict): raise ValueError("Unsupported JSON root")
    out = []
    if "snapshots" in doc:
        for i, snapshot in enumerate(doc["snapshots"]):
            system, collection = snapshot["data_store"], snapshot["collection"]
            when = snapshot["captured_at"]
            category = CATEGORIES.get(collection, "")
            records = snapshot["records"]
            declared_scope=snapshot.get('scope',{})
            full=snapshot.get("complete") is True or declared_scope.get('type')=='full_collection'
            scope=scope_fact(eid, f"/snapshots/{i}", captured, when, system, category, "logical", [r["resource_id"] for r in records],full)
            out.append(scope)
            for j, record in enumerate(records):
                out.append(record_fact(record, evidence_id=eid, locator=f"/snapshots/{i}/records/{j}", available=captured,
                                       observed=when, system=system, collection=collection))
    elif "service_exports" in doc:
        for system, groups in doc["service_exports"].items():
            for collection, records in groups.items():
                for i, record in enumerate(records):
                    kw = dict(evidence_id=eid, locator=f"/service_exports/{system}/{collection}/{i}", available=captured,
                              observed=record["observed_at"], system=system, collection=collection)
                    if collection == "index_queries":
                        hits = record["hits"]
                        if hits["total"] == 0:
                            out.append(record_fact(record, **kw, state="ABSENT"))
                        else:
                            for child in hits["documents"]:
                                out.append(record_fact(dict(child, query=record["query"]), **kw))
                    else: out.append(record_fact(record, **kw))
    elif "records" in doc:
        records = doc["records"]
        if "record_count" in doc and doc["record_count"] != len(records): raise ValueError("Declared record_count mismatch")
        for i, record in enumerate(records):
            system = record.get("system") or {"analytics_identity_store": "analytics_platform", "customer_export_service": "export_service", "export_service": "export_service"}.get(doc.get("source"))
            if not system:
                collection = doc.get("collection", "")
                system = {"customer_export_jobs": "export_service", "customer_analytics_reports": "analytics_platform"}.get(collection)
            if not system: raise ValueError("JSON record has no grounded system mapping")
            out.append(record_fact(record, evidence_id=eid, locator=f"/records/{i}", available=captured,
                                   observed=record.get("recorded_at", doc.get("captured_at", captured)), system=system,
                                   collection=doc.get("collection", "")))
    else: raise ValueError("Unsupported JSON evidence schema")
    return out


def activity_facts(rows: list[dict]) -> list[Fact]:
    out = []
    for n, row in enumerate(rows, 2):
        system = row["target_system"]
        if row["event_type"] == "RESTORE_BACKUP": system = row["source_system"]
        kind = "LINK" if row["event_type"] == "LINK_RESOURCE_IDENTITY" else "CLAIM"
        details = row["details"]
        category = "USER_PROFILE" if "primary profile" in details else ""
        out.append(record_fact(dict(row, resource_id=row["resource_id"]), evidence_id=row["activity_id"], locator=f"system_activity.csv:{n}",
                               available=row["event_time"], observed=row["event_time"], system=system, category=category,
                               links=tokens(details), kind=kind, state=""))
        if row["event_type"] in {"RESTORE_BACKUP","SYNC_RECORD"}:
            target=re.search(r"\b(?:downstream|target) resource ([A-Za-z][A-Za-z0-9_]*)\b",details)
            if target:
                out.append(record_fact(dict(row,resource_id=target[1]),evidence_id=row["activity_id"],locator=f"system_activity.csv:{n}/target",
                                       available=row["event_time"],observed=row["event_time"],system=row["target_system"],kind="CLAIM"))
    return out
