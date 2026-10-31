"""Fictional, independent audit fixtures; no participant labels or copied records."""
from audit.contracts import Fact, Request, Resource, timestamp
from audit.inputs import Dataset

START = "2026-01-01T00:00:00Z"
CUTOFF = "2026-01-31T00:00:00Z"
PERSON = {"user_id":"user_fixture", "name":"Fixture Person", "email":"fixture@example.test", "phone":"+1 555 0100", "email_hash":"c"*64,"updated_at":START}
RULES = [
    ("USER_PROFILE", "Always", "DELETE"),
    ("SEARCH_INDEX_ENTRY", "Always", "DELETE"),
    ("SECONDARY_IDENTIFIER", "Always", "DELETE"),
    ("CACHE_ENTRY", "Always", "DELETE"),
    ("MARKETING_PROFILE", "Always", "DELETE"),
    ("SUPPORT_MESSAGE", "Conversation contains shared customer, agent, or order context that must be retained", "REDACT"),
    ("SUPPORT_ATTACHMENT", "Attachment belongs only to the deletion subject", "DELETE"),
    ("ANALYTICS_PROFILE", "Record is still attributable to a user", "ANONYMIZE"),
    ("PRODUCT_TELEMETRY", "Record is still attributable to a user", "ANONYMIZE"),
    ("ACCOUNT_TOMBSTONE", "Account is deleted and only a stable internal user_id is needed to preserve references to retained records", "REDACT"),
    ("SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN"),
    ("LEGAL_HOLD_RECORD", "A supplied legal hold is active", "RETAIN"),
    ("BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN"),
    ("EMAIL_DELIVERY_LOG", "Log contains a user email address", "REDACT"),
]


def request(text="Please delete my account."):
    return Request("fixture_case", PERSON["email"], timestamp(START), "COMPLETE", timestamp(START), timestamp(CUTOFF), text)


def observed(system="account_service", resource="fixture_account", category="USER_PROFILE", state="ABSENT", when=START,
             available=None, store="logical", links=("user_fixture",), **fields):
    return Fact("fixture_"+resource, "fixture", timestamp(when), timestamp(available or when), Resource(system, resource), category,
                "OBSERVATION", store, fields, links, state, frozenset(fields))


def dataset(facts=None):
    return Dataset(facts=list(facts) if facts is not None else [observed()], identities=[dict(PERSON)],
                   rules=[{"rule_id":"fixture_rule_"+str(i), "data_category":cat,"condition":cond,"required_action":action} for i,(cat,cond,action) in enumerate(RULES)])
