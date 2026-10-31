"""Choose a proving visible ID without relying on file order or numeric suffixes."""
from .contracts import Fact


def choose(facts: list[Fact], cutoff) -> str:
    candidates = [f for f in facts if f.kind == "OBSERVATION" and f.admitted(cutoff)]
    if not candidates: raise ValueError("No admissible observation proves this step")
    latest = max(f.observed for f in candidates)
    finalists = [f for f in candidates if f.observed == latest]
    return min(finalists, key=lambda f: (f.evidence_id, f.locator)).evidence_id
