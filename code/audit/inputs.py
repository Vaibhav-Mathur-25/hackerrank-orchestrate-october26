"""Capability-style participant input access. Gold and output templates are denied."""
from __future__ import annotations
import csv
import hashlib
import io
from pathlib import Path
from dataclasses import dataclass, field
from .contracts import Fact, Issue, Request
from .extractors.csv_json import json_facts, activity_facts
from .extractors.sql import sql_facts

CSV_INPUTS = {"sample_deletion_requests.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv", "deletion_rules.csv", "evidence_files.csv"}


class Inputs:
    def __init__(self, root: Path, requests_file="sample_deletion_requests.csv"):
        if requests_file not in {"sample_deletion_requests.csv","deletion_requests.csv"}:
            raise PermissionError('Unsupported request source')
        self.root = root.resolve()
        self.allowed=CSV_INPUTS | ({"deletion_requests.csv"} if requests_file=="deletion_requests.csv" else set())
        self.accessed: list[str] = []
        self.hashes: dict[str,str] = {}

    def read(self, relative: str, *, evidence=False) -> bytes:
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root): raise ValueError("Input path escapes dataset")
        if not evidence and relative not in self.allowed: raise PermissionError("Not a prediction input: " + relative)
        if evidence and not path.is_relative_to(self.root / "evidence"): raise PermissionError("Evidence path outside evidence directory")
        self.accessed.append(relative)
        data=path.read_bytes()
        self.hashes[relative]=hashlib.sha256(data).hexdigest()
        return data

    def csv(self, name: str) -> list[dict]:
        reader = csv.DictReader(io.StringIO(self.read(name).decode("utf-8-sig"), newline=""))
        rows = list(reader)
        if len(reader.fieldnames or []) != len(set(reader.fieldnames or [])): raise ValueError("Duplicate CSV columns")
        if any(None in row or any(v is None for v in row.values()) for row in rows): raise ValueError("Malformed CSV")
        return rows


@dataclass
class Dataset:
    facts: list[Fact] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    identities: list[dict] = field(default_factory=list)
    audits: list[dict] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    accessed: list[str] = field(default_factory=list)
    input_hashes: dict[str,str] = field(default_factory=dict)


def load_dataset(root: Path, cache: Path | None = None, requests_file="sample_deletion_requests.csv") -> Dataset:
    source = Inputs(root,requests_file)
    result = Dataset(identities=source.csv("user_identities.csv"), audits=source.csv("user_audit_log.csv"), rules=source.csv("deletion_rules.csv"))
    result.requests = [Request.from_row(row) for row in source.csv(requests_file)]
    if len({r.case_id for r in result.requests}) != len(result.requests): raise ValueError("Duplicate request ID")
    result.facts.extend(activity_facts(source.csv("system_activity.csv")))
    manifest = source.csv("evidence_files.csv")
    if len({m["file_id"] for m in manifest}) != len(manifest) or len({m["file_path"] for m in manifest}) != len(manifest):
        raise ValueError("Duplicate evidence manifest identity")
    for item in sorted(manifest, key=lambda m: m["file_id"]):
        artifact = dict(item)
        try:
            data = source.read(item["file_path"], evidence=True)
            artifact["sha256"] = hashlib.sha256(data).hexdigest()
            suffix = Path(item["file_path"]).suffix
            if suffix == ".json": facts = json_facts(data, item["file_id"], item["captured_at"])
            elif suffix == ".sql": facts = sql_facts(data, item["file_id"], item["captured_at"])
            elif suffix == ".log":
                from .extractors.logs import log_facts
                facts = log_facts(data, item["file_id"], item["captured_at"])
            elif suffix in {".pdf", ".png", ".txt"}:
                from .extractors.documents import document_facts
                facts, warnings = document_facts(data, suffix, item["file_id"], item["captured_at"], cache)
                result.issues.extend(warnings)
            else: raise ValueError("Unsupported evidence format")
            result.facts.extend(facts)
            artifact.update(status="parsed", fact_count=len(facts))
        except Exception as error:
            artifact.update(status="failed", fact_count=0)
            result.issues.append(Issue("INGESTION_FAILURE", "ingestion", f"{item['file_path']}: {error}", evidence_ids=(item["file_id"],)))
        result.artifacts.append(artifact)
    result.accessed = source.accessed
    result.input_hashes = source.hashes
    from .entity_links import link_entities, resource_links,corroborate_identifiers
    result.facts.extend(link_entities(result.facts))
    result.facts.extend(resource_links(result.facts))
    result.facts.extend(corroborate_identifiers(result.facts))
    return result
