"""Format-independent record normalization. Category comes from artifact semantics."""
from __future__ import annotations
import re
from .contracts import Fact, Resource, timestamp

CATEGORIES = {
    "customer_profiles": "USER_PROFILE", "profile_lookups": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY", "search_documents_primary": "SEARCH_INDEX_ENTRY", "index_queries": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE", "customer_analytics_profiles": "ANALYTICS_PROFILE", "profiles": "ANALYTICS_PROFILE",
    "support_conversations": "SUPPORT_MESSAGE", "support_records": "SUPPORT_MESSAGE", "tickets": "SUPPORT_MESSAGE",
    "support_attachments": "SUPPORT_ATTACHMENT", "customer_export_jobs": "USER_EXPORT", "customer_exports": "USER_EXPORT", "exports": "USER_EXPORT",
    "connector_configurations": "DATA_FLOW", "connector_subscriptions": "DATA_FLOW", "connectors": "DATA_FLOW",
    "backup_catalog": "BACKUP_ARCHIVE", "backup_restore_entries": "BACKUP_ARCHIVE", "restore_entries": "BACKUP_ARCHIVE",
    "security_audit_events": "SECURITY_AUDIT_LOG", "security_audit_records": "SECURITY_AUDIT_LOG", "audit_records": "SECURITY_AUDIT_LOG",
    "retained_order_records": "LEGAL_HOLD_RECORD", "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG", "marketing_profiles": "MARKETING_PROFILE", "product_telemetry": "PRODUCT_TELEMETRY",
}
TABLE_SYSTEMS = {
    "customer_profiles": "account_service", "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
    "customer_exports": "export_service", "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
    "search_documents_primary": "search_service",
}
ALIASES = {"customer_reference": "user_id", "subject_reference": "user_id", "full_name": "name", "display_name": "name",
           "requester_name": "name", "requester_email": "email", "requester_phone": "phone",
           "owner_email": "email", "owner_phone": "phone", "customer_email": "email",
           "message_text": "text", "message_excerpt": "text", "retained_until": "retention_until"}
LINK_KEYS = {"user_id", "customer_reference", "subject_reference", "subject_ref", "subject_selector", "email", "phone", "email_hash", "requester_email", "requester_phone", "owner_email", "owner_phone", "customer_email", "lookup_value", "lookup_key", "correlation_key", "query", "matched_value", "scan_key", "uploaded_by"}
TOKEN = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\buser_[A-Za-z0-9]+\b|\b[a-fA-F0-9]{64}\b")


def tokens(value) -> tuple[str, ...]:
    # Structured selectors are query metadata. Only declared identity keys
    # participate; neighboring results and arbitrary payload text never do.
    if isinstance(value, dict):
        return tuple(t for k, v in value.items() if k in LINK_KEYS for t in tokens(v))
    if not isinstance(value, str): return ()
    found = TOKEN.findall(value)
    if value.strip().startswith("+") and re.fullmatch(r"[+\d ()-]+", value.strip()): found.append(value.strip())
    return tuple(found)


def normalize_fields(record: dict) -> dict:
    result = {}
    for key, value in record.items():
        if key in {"profile", "document"} and isinstance(value, dict):
            result.update(normalize_fields(value))
        elif key not in {"resource_id", "observed_at", "recorded_at", "captured_at", "updated_at"}:
            canonical = ALIASES.get(key, "user_id" if key == "subject_ref" else key)
            # subject_reference may contain an email rather than an internal ID.
            if canonical == "user_id" and isinstance(value, str) and "@" in value:
                result["email"] = value
            else: result[canonical] = value
    if "record_type" in record and "result" in record and "subject_reference" in record:
        # A lookup export reports which subject was queried, not necessarily a
        # field remaining in the returned record (notably ANONYMIZED results).
        result.pop("user_id", None)
        if "@" in str(record["subject_reference"]): result.pop("email", None)
        result["lookup_subject"] = record["subject_reference"]
    for key in ["enabled", "restore_allowed"]:
        if type(result.get(key)) is int and result[key] in (0, 1): result[key] = bool(result[key])
    return result


def record_fact(record: dict, *, evidence_id: str, locator: str, available, observed,
                system: str, collection: str = "", store: str = "logical", category: str = "",
                links: tuple[str, ...] = (), state: str = "", kind: str = "OBSERVATION") -> Fact:
    fields = normalize_fields(record)
    gathered = list(links)
    for key, value in record.items():
        if key in LINK_KEYS: gathered.extend(tokens(value))
        if key in {"profile", "document"} and isinstance(value, dict):
            for k, v in value.items():
                if k in LINK_KEYS: gathered.extend(tokens(v))
    result = record.get("result", "")
    if not state:
        state = {"NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT", "REDACTED": "REDACTED",
                 "ANONYMIZED": "ANONYMIZED", "ACTIVE": "ACTIVE", "DISABLED": "DISABLED", "BLOCKED": "BLOCKED"}.get(result, "PRESENT")
        if record.get("status_code") == 404: state = "ABSENT"
    resolved_category = category or record.get("record_type", "") or CATEGORIES.get(collection, "")
    coverage = set(fields)
    if resolved_category == "ANALYTICS_PROFILE" and {"user_id","email","phone","email_hash"} <= coverage and (collection in {"profiles","customer_analytics_profiles","customer_analytics_reports"} or record.get("event") == "analytics_profile_read_completed"):
        # These declared readback schemas have no name column. Generic partial
        # observations must explicitly cover it before proving anonymization.
        coverage.add("name")
    if resolved_category == "SUPPORT_MESSAGE" and {"name", "email", "phone"} <= coverage and (collection in {"tickets","support_records"} or record.get("event") == "support_ticket_read_completed"):
        # The ticket readback's declared schema covers its direct identifier
        # columns; no email_hash column exists in that representation.
        coverage.add("email_hash")
    return Fact(evidence_id, locator, timestamp(observed), timestamp(available), Resource(system, record.get("resource_id", "")),
                resolved_category, kind, store, fields, tuple(sorted(set(gathered))), state, frozenset(coverage))


def collection_category(name: str) -> str:
    if name.startswith("customer_profiles_"): return "USER_PROFILE"
    return CATEGORIES.get(name, "")
