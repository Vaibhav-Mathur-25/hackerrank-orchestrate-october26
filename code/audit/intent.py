"""Conservative multilingual request authorization. No case IDs or label lookup."""
from dataclasses import dataclass
import re
import unicodedata


@dataclass(frozen=True)
class Intent:
    authorized: bool | None
    reason: str


def classify(text: str) -> Intent:
    t = unicodedata.normalize("NFKC", text).casefold().replace("’", "'")
    negative = [r"\b(?:do not|don't)\s+(?:delete|erase|close)(?: or change)?\s+(?:(?:my|the|this|that)\s+)?(?:account|profile|anything|it)\b",
                r"\b(?:do not|don't)\s+(?:delete|erase|remove)\s+(?:only\s+)?(?:(?:my|the|this)\s+)?(?:attachment|export|search result|marketing profile)\b",
                r"\b(?:not asking for deletion|not a request to erase)",
                r"\b(?:leave|keep) (?:my |the )?(?:account|profile).{0,35}(?:active|as it is|in place)",
                r"\b(?:marketing|promotional).{0,30}(?:only|not asking for deletion)",
                r"continue using (?:the service|this account)"]
    deletion = [r"\b(?:delete|remove)\s+only\s+(?:the\s+|my\s+)?(?:attachment|export|search result|marketing profile)\b",
                r"\b(?:delete|erase|remove|deleting|deletion|closed|close).{0,90}(?:account|profile|personal|details|records)",
                r"\b(?:account|profile|personal data).{0,90}(?:deleted|deleting|erased|removed|deletion|gone|closed)",
                r"suppression d[eé]finitive", r"eliminaci[oó]n", r"exclus[aã]o permanente", r"完全な削除", r"영구 삭제"]
    is_negative = any(re.search(p, t) for p in negative)
    is_delete = any(re.search(p, t) for p in deletion)
    if is_negative:
        remainder=t
        for pattern in negative: remainder=re.sub(pattern,"",remainder)
        if re.search(r"\b(?:please\s+)?(?:delete|erase|close|remove)\s+(?:(?:my|the|this)\s+)?(?:account|profile)\b",remainder):
            return Intent(None,"Contradictory account deletion and preservation instructions")
        # Explicit preservation and requests limited to access/correction/opt-out
        # are outside the challenge's authorized deletion workflow.
        return Intent(False, "Explicit account preservation/non-deletion scope")
    if is_delete: return Intent(True, "Explicit deletion or deletion-audit request")
    if any(re.search(p, t) for p in [r"\b(?:export|download|copy|portable|access|reset|correct|replace|change).{0,80}(?:account|information|invoices|profile|email|number|login|surname)",
                                   r"\b(?:surname|name).{0,60}(?:misspelled|incorrect|wrong).{0,80}(?:correct|fix)\b",
                                   r"stop (?:the )?promotional emails", r"information request"]):
        return Intent(False, "Access, correction, recovery, or marketing-only request")
    return Intent(None, "Unrecognized or ambiguous authorization; interpretation required")
