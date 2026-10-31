"""Parse supported log encodings and correlate query/result lines by scoped trace."""
from __future__ import annotations
import json
import re
from ..contracts import Fact
from ..normalize import LINK_KEYS, record_fact, tokens

KV = re.compile(r'''([A-Za-z_][\w.-]*)=("(?:\\.|[^"\\])*"|'[^']*'|[^\s|]+)''')
EVENTS = {
    "profile_lookup_completed": "USER_PROFILE", "index_query_completed": "SEARCH_INDEX_ENTRY",
    "audit_record_read_completed": "SECURITY_AUDIT_LOG", "connector_heartbeat": "DATA_FLOW",
    "connector_config_loaded": "DATA_FLOW", "connector_config_read_completed": "DATA_FLOW",
    "analytics_identity_scan": "ANALYTICS_PROFILE", "analytics_profile_read": "ANALYTICS_PROFILE",
    "analytics_profile_read_completed": "ANALYTICS_PROFILE", "message_pii_scan": "SUPPORT_MESSAGE",
    "message_read": "SUPPORT_MESSAGE", "support_ticket_read_completed": "SUPPORT_MESSAGE",
    "attachment_pii_scan": "SUPPORT_ATTACHMENT", "contact_query_completed": "SECONDARY_IDENTIFIER",
    "contact_lookup_completed": "SECONDARY_IDENTIFIER", "restore_candidate_evaluated": "BACKUP_ARCHIVE",
    "restore_authorization_completed": "BACKUP_ARCHIVE", "restore_policy_read_completed": "BACKUP_ARCHIVE",
    "export_download_check_completed": "USER_EXPORT", "export_metadata_read_completed": "USER_EXPORT",
    "retained_order_loaded": "LEGAL_HOLD_RECORD",
}


def scalar(value):
    if not isinstance(value, str): return value
    if value in {"null", "None"}: return None
    if value.lower() in {"true", "false"}: return value.lower() == "true"
    if re.fullmatch(r"-?\d+", value): return int(value)
    return value


def key_values(text):
    out = {}
    for key, value in KV.findall(text):
        if value.startswith('"'):
            try: value = json.loads(value)
            except json.JSONDecodeError: raise ValueError("Malformed quoted log value")
        elif value.startswith("'"): value = value[1:-1]
        out[key] = scalar(value)
    return out


def parse_line(line: str) -> dict:
    first, _, rest = line.partition(" ")
    out = {"time": first}
    if rest.startswith("{"):
        out.update({k: scalar(v) for k, v in json.loads(rest).items()})
    else:
        out.update(key_values(rest))
        if "message" in out and isinstance(out["message"], str):
            out.update(key_values(out["message"]))
            out.setdefault("service", out.get("function"))
            out.setdefault("trace_id", out.get("requestId"))
        bracket = re.match(r"\[[^]]+\] \[([^]]+)\] \[([^]]+)\] ([a-z_]+):", rest)
        if bracket: out.update(service=bracket[1], trace_id=bracket[2], event=bracket[3])
        if " | " in rest:
            parts = [p.strip() for p in rest.lstrip("| ").split("|")]
            if len(parts) >= 5: out.update(service=parts[1], trace_id=parts[2], event=parts[3])
        syslog = re.match(r"<\d+>1 \S+ (\S+) (\S+) - - ", rest)
        if syslog: out.update(service=syslog[1], trace_id=syslog[2])
    return out


def log_facts(data: bytes, eid: str, captured: str) -> list[Fact]:
    rows = []
    for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if line.strip(): rows.append((n, parse_line(line)))
    # Sort before correlation; input shuffling cannot connect the wrong attempt.
    rows.sort(key=lambda pair: (pair[1]["time"], 0 if str(pair[1].get("event", "")).endswith("_started") else 1,
                                json.dumps(pair[1], sort_keys=True)))
    contexts = {}
    out = []
    for n, row in rows:
        service = row.get("service", "")
        trace = row.get("trace_id")
        # Trace identifiers can be reused by separate instances/requests.
        key = (service, row.get("instance", ""), trace)
        event = row.get("event", "")
        previous = contexts.get(key, {}) if trace else {}
        if event.endswith("_started") and trace:
            contexts[key] = dict(row, _line=n)
            continue
        if previous.get("resource_id") and row.get("resource_id") and previous["resource_id"] != row["resource_id"]:
            previous = {}
        if previous.get("attempt") is not None and row.get("attempt") is not None and previous["attempt"] != row["attempt"]:
            previous = {}
        category = row.get("record_type") if event == "record_lookup" else EVENTS.get(event)
        if not category or not row.get("resource_id"): continue
        # A completion consumes its query context, preventing a later orphaned
        # completion from inheriting an unrelated customer's selector.
        if trace: contexts.pop(key, None)
        system = row.get("system", service)
        if system == "support_replica": system = "support_platform"
        links = []
        for source in (previous, row):
            for k, v in source.items():
                if k in LINK_KEYS or k in {"match_key", "subject_key"}: links.extend(tokens(v))
        body = dict(row)
        # Explicit readback targets can be aligned with SQL stores. A pool name
        # or generic service label alone is not a topology assertion.
        physical=row.get('physical_store') or row.get('read_store') or previous.get('physical_store') or previous.get('read_store')
        if isinstance(physical,str) and physical:body['physical_store']=physical
        state = ""
        failed = (isinstance(row.get("http_status"), int) and row["http_status"] >= 400 and row["http_status"] != 404) or str(row.get("result", "")).lower() in {"failed", "error", "timeout"}
        if category in {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER"}:
            if row.get("rows") == 0 or row.get("http_status") == 404 or row.get("result") == "miss" or row.get("total_hits") == 0: state = "ABSENT"
        if category == "DATA_FLOW":
            if type(row.get("enabled")) is bool: state = "ACTIVE" if row["enabled"] else "DISABLED"
        if category == "BACKUP_ARCHIVE":
            if "eligible" in row: body["restore_allowed"] = row["eligible"] and not row.get("deletion_block", False)
            if "decision" in row: body["restore_allowed"] = {"deny": False, "allow": True}.get(row["decision"])
            if type(body.get("restore_allowed")) is bool: state = "ACTIVE" if body["restore_allowed"] else "BLOCKED"
        # Scan results are observations of identifying content, not a stored query key.
        if "matched_value" in row: body["detected_identifier"] = row["matched_value"]
        if category == "ANALYTICS_PROFILE" and row.get("direct_identifiers") == 0:
            body["identifier_scan_clear"] = True
        if event == "message_read" and row.get("message_text") == "[REDACTED]": state = "REDACTED"
        locator = f"lines:{previous['_line']}-{n}" if previous else f"line:{n}"
        store = "support_replica" if service == "support_replica" else "logical"
        out.append(record_fact(body, evidence_id=eid, locator=locator, available=captured, observed=row["time"],
                               system=system, category=category, links=tuple(links), state=state, store=store,
                               kind="CLAIM" if failed else "OBSERVATION"))
    return out
