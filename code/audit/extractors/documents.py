"""PDF, PNG and handover extraction with conservative business-artifact adapters.

OCR text is cached by content and engine version. Ambiguous image fields are not
silently made authoritative. Source text is retained in local caches, not source.
"""
from __future__ import annotations
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from ..contracts import Fact, Issue, Resource, timestamp
from ..normalize import record_fact, tokens

OCR_ADAPTER_VERSION = "4"
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
ENTITY_REF = re.compile(r"\b(?:NST-\d{4}-\d{4}-\d+|ORD-\d+|CS-\d+|delivery_confirmation_\d+\.pdf)\b")


def extract_text(data: bytes, suffix: str, cache: Path | None, psm=3):
    if suffix == ".txt": return data.decode("utf-8"), []
    if suffix == ".pdf":
        from pypdf import PdfReader
        pages = PdfReader(io.BytesIO(data)).pages
        text = "\n\f\n".join(page.extract_text(extraction_mode="layout") or "" for page in pages)
        if not text.strip(): raise ValueError("PDF has no extractable text; image interpretation required")
        return text, []
    if suffix != ".png": raise ValueError("Unsupported document extension")
    from PIL import Image
    with Image.open(io.BytesIO(data)) as image: image.verify()
    if not shutil.which("tesseract"): raise RuntimeError("Tesseract is unavailable")
    version = subprocess.run(["tesseract", "--version"], capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()[0]
    key = hashlib.sha256(data + version.encode() + OCR_ADAPTER_VERSION.encode() + str(psm).encode()).hexdigest()
    path = cache / (key + ".ocr.json") if cache else None
    if path and path.exists():
        saved = json.loads(path.read_text()); return saved["text"], saved["low_confidence"]
    with tempfile.TemporaryDirectory(prefix="audit-ocr-") as tmp:
        png = Path(tmp) / "input.png"; png.write_bytes(data)
        proc = subprocess.run(["tesseract", str(png), "stdout", "--psm",str(psm), "tsv"], capture_output=True, text=True, timeout=60, check=True)
    import csv
    rows = list(csv.DictReader(io.StringIO(proc.stdout), delimiter="\t"))
    lines, low = {}, []
    for row in rows:
        word = row["text"].strip()
        if not word: continue
        line = tuple(row[k] for k in ["page_num", "block_num", "par_num", "line_num"])
        lines.setdefault(line, []).append(word)
        if float(row["conf"]) < 65 and ("@" in word or re.search(r"(?:account|analytics|support|search|backup|marketing|audit_record|data_flow|export)_", word)):
            low.append(word)
    text = "\n".join(" ".join(words) for words in lines.values())
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"text": text, "low_confidence": low, "engine": version}, ensure_ascii=False))
    return text, low


def selected_panel_text(data, cache):
    """Detail panel in the declared desktop admin-console layout.

    The caller requires a recognized app and exact field labels. Coordinates
    select a UI region, never a subject. Unrecognized layouts fall back to the
    conservative row parser. History entries are excluded by the caller.
    """
    from PIL import Image, UnidentifiedImageError
    try:
        with Image.open(io.BytesIO(data)) as image:
            width,height=image.size
            if width < 1000 or width/height < 1.4: return "", []
            panel=image.crop((int(width*.79),int(height*.28),width,int(height*.70)))
            stream=io.BytesIO();panel.save(stream,format="PNG")
    except UnidentifiedImageError:
        return "", []
    return extract_text(stream.getvalue(),'.png',cache,psm=6)


def handover_facts(text, eid, captured):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.startswith("- "): continue
        parts = [p.strip() for p in line[2:].split("|")]
        if len(parts) != 6: raise ValueError("Malformed handover entry")
        when, system, resource, category, result, subject = parts
        out.append(record_fact({"resource_id": resource, "record_type": category, "result": result, "subject_reference": subject},
                               evidence_id=eid, locator=f"line:{n}", available=captured, observed=when, system=system))
    if not out: raise ValueError("Unsupported plain-text evidence")
    return out


def document_facts(data: bytes, suffix: str, eid: str, captured: str, cache: Path | None = None):
    text, low = extract_text(data, suffix, cache)
    if suffix == ".txt": return handover_facts(text, eid, captured), []
    warnings = []
    if low:
        warnings.append(Issue("OCR_UNCERTAINTY", "documents", "Low-confidence identifying tokens need visual verification.", evidence_ids=(eid,), blocking=False,
                              investigation="Inspect image regions and compare OCR identifiers with independent sources."))
    lower = text.lower()
    emails = sorted(set(EMAIL.findall(text)))
    subject_links = tuple(sorted(set(tokens(text))))
    out = []
    if suffix == ".pdf":
        # A multi-subject register is a set of row-scoped instruments. Joining
        # all document users to each row would falsely merge unrelated people.
        register_rows=[]
        for n,line in enumerate(text.splitlines(),1):
            match=re.search(r"\b(ORD-\d+)\s*\|\s*(user_[A-Za-z0-9]+)\s*\|.*?\bRetain until\s+(\d{1,2}\s+[A-Za-z]+\s+\d{4})",line,re.I)
            if not match:continue
            body={"text":line.strip(),"document_refs":[match[1]],"retention_date":match[3]}
            # The register explicitly declares UTC. A date-only retain-until
            # includes that calendar day; timestamp-valued periods stay exact.
            if "UTC" in text:
                from datetime import datetime,timezone,timedelta
                for fmt in ("%d %b %Y","%d %B %Y"):
                    try:
                        body["retention_until"]=(datetime.strptime(match[3],fmt).replace(tzinfo=timezone.utc)+timedelta(days=1)).isoformat()
                        break
                    except ValueError:continue
            register_rows.append(Fact(eid,f"pdf-text-line:{n}",timestamp(captured),timestamp(captured),
                                      Resource("legal_service",""),"LEGAL_HOLD_RECORD","ENTITY",
                                      fields=body,links=(match[2],)))
        if register_rows:
            warnings.append(Issue("DOCUMENT_ENTITY_UNLINKED","documents","Row-scoped retention instruments need an explicit business-reference/resource mapping.",evidence_ids=(eid,),blocking=False))
            return register_rows,warnings
        if "support_" in text and "attachment" in lower:
            resource = re.search(r"\bsupport_\d+\b", text)
            form = re.sub(r"\s+", " ", lower)
            sole_subject = len(emails) == 1 and ("belongs only" in form or ("delivery address correction request" in form and "uploader customer" in form))
            out.append(record_fact({"resource_id": resource[0], "text": text, "exclusive_subject": sole_subject},
                                   evidence_id=eid, locator="pages:all", available=captured, observed=captured,
                                   system="support_platform", category="SUPPORT_ATTACHMENT", links=subject_links))
        elif "retain until" in lower and "audit_record_" in text:
            resource = re.search(r"\baudit_record_\d+\b", text)
            # Parse the supplied date; no default retention duration is invented.
            date = re.search(r"retain until\s+(\d{1,2}\s+[A-Za-z]+\s+\d{4})(?:\s+(\d{2})\s*[: ]\s*(\d{2}))?", text, re.I)
            body = {"resource_id": resource[0], "text": text}
            if date:
                from datetime import datetime, timezone
                dt = datetime.strptime(date[1], "%d %b %Y").replace(tzinfo=timezone.utc, hour=int(date[2] or 0), minute=int(date[3] or 0))
                body["retention_until"] = dt.isoformat()
            out.append(record_fact(body, evidence_id=eid, locator="pages:all", available=captured, observed=captured,
                                   system="security_service", category="SECURITY_AUDIT_LOG", links=subject_links))
        else:
            category = "LEGAL_HOLD_RECORD" if "retain until" in lower else "USER_EXPORT" if "customer statement" in lower else ""
            system = "legal_service" if category == "LEGAL_HOLD_RECORD" else "export_service" if category else ""
            out.append(Fact(eid, "pages:all", timestamp(captured), timestamp(captured), Resource(system, ""), category,
                            "ENTITY", fields={"text": text, "document_refs": ENTITY_REF.findall(text)}, links=subject_links))
            warnings.append(Issue("DOCUMENT_ENTITY_UNLINKED", "documents", "Document decoded; resource mapping/conditional retention requires a grounded link.", evidence_ids=(eid,), blocking=False))
        return out, warnings
    # Screens are parsed only when the page's business context establishes category.
    contexts = [
        ("audience operations", "marketing_platform", "MARKETING_PROFILE", "marketing"),
        ("pulse analytics", "analytics_platform", "ANALYTICS_PROFILE", "analytics"),
        ("customer operations", "account_service", "USER_PROFILE", "account"),
        ("search console", "search_service", "SEARCH_INDEX_ENTRY", "search"),
        ("helpline console", "support_platform", "SUPPORT_MESSAGE", "support"),
        ("sentinel", "security_service", "SECURITY_AUDIT_LOG", "audit_record"),
        ("bridgeops", "integration_service", "DATA_FLOW", "data_flow"),
        ("vault recovery", "backup_service", "BACKUP_ARCHIVE", "backup"),
        ("customer download", "export_service", "USER_EXPORT", "export"),
    ]
    context = next((x for x in contexts if x[0] in lower), None)
    if not context:
        out.append(Fact(eid, "image:all", timestamp(captured), timestamp(captured), Resource("", ""), kind="ENTITY",
                        fields={"text": text, "document_refs": ENTITY_REF.findall(text)}, links=subject_links))
        warnings.append(Issue("SCREEN_MAPPING_UNSUPPORTED", "documents", "Image decoded but cannot prove a resource/category mapping.", evidence_ids=(eid,), blocking=False))
        return out, warnings
    _, system, category, prefix = context
    if category in {'SEARCH_INDEX_ENTRY','SECURITY_AUDIT_LOG'}:
        panel,panel_low=selected_panel_text(data,cache)
        detail=re.split(r'\bActivity\b',panel,flags=re.I)[0]
        ids=set(re.findall(r'\b'+prefix+r'_\d+\b',detail))
        subjects=set(re.findall(r'^\s*(?:customer_reference|subject)\s+(user_[A-Za-z0-9]+)\s*$',detail,re.M))
        if len(ids)==len(subjects)==1:
            rid=next(iter(ids));uid=next(iter(subjects))
            body={'resource_id':rid,'user_id':uid}
            critical={rid,uid}
            if any(any(v in token for token in panel_low) for v in critical):body['extraction_uncertain']=True
            # Stored email OCR is optional for these predicates: the selected
            # resource and stable customer reference ground presence. A low-
            # confidence neighboring/history email never becomes ownership.
            return [record_fact(body,evidence_id=eid,locator='image:detail-panel[x=.79:1,y=.28:.70]',
                                available=captured,observed=captured,system=system,category=category)],warnings
    if context[0] in {"bridgeops", "customer download", "vault recovery"}:
        panel, panel_low=selected_panel_text(data,cache)
        detail=re.split(r"\bActivity\b",panel,flags=re.I)[0]
        ids=re.findall(r"\b"+prefix+r"_\d+\b",detail)
        label={"DATA_FLOW":"Selector", "USER_EXPORT":"Owner", "BACKUP_ARCHIVE":"Account"}[category]
        selected=re.findall(r"^\s*[‘']?"+label+r"\s+([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})\s*$",detail,re.M)
        if len(set(ids))==1 and len(set(selected))==1:
            body={"resource_id":ids[0],"email":selected[0]}
            if category=="DATA_FLOW" and "continuous sync" in detail.lower(): body["enabled"]=True
            if category=="DATA_FLOW" and re.search(r"\bSync mode\s+Disabled\b",detail,re.I): body["enabled"]=False
            used={ids[0],selected[0]}
            uncertain=[v for v in used if any(v in token for token in panel_low)]
            if uncertain: body.update(extraction_uncertain=True,uncertain_values=sorted(uncertain))
            return [record_fact(body,evidence_id=eid,locator="image:detail-panel[x=.79:1,y=.28:.70]",
                                available=captured,observed=captured,system=system,category=category)],warnings
    # Main selected panel is generally repeated. Select only an unambiguous ID,
    # or the most frequently repeated exact ID; never repair OCR punctuation.
    from collections import Counter
    counts = Counter(re.findall(r"\b" + prefix + r"_\d+\b", text))
    if not counts:
        warnings.append(Issue("SCREEN_RESOURCE_UNREADABLE", "documents", "No exact resource ID extracted from business screen.", evidence_ids=(eid,), blocking=False))
        return [], warnings
    winners = [r for r, n in counts.items() if n == max(counts.values())]
    if len(winners) != 1 or len(emails) > 1:
        # Multi-row screenshots need row-level provenance; global association is unsafe.
        for n, line in enumerate(text.splitlines(), 1):
            resources = re.findall(r"\b" + prefix + r"_\d+\b", line)
            addresses = EMAIL.findall(line)
            if len(resources) == 1 and len(addresses) == 1:
                out.append(record_fact({"resource_id": resources[0], "email": addresses[0]}, evidence_id=eid,
                                       locator=f"ocr-line:{n}", available=captured, observed=captured, system=system, category=category))
        warnings.append(Issue("SCREEN_PARTIAL_COVERAGE", "documents", "Only unambiguous resource/email rows extracted; other screen associations need review.", evidence_ids=(eid,), blocking=False))
    else:
        body = {"resource_id": winners[0]}
        if emails: body["email"] = emails[0]
        # Health labels and encryption are not proof of disabled synchronization or blocked restore.
        if category == "DATA_FLOW" and "continuous sync" in lower: body["enabled"] = True
        out.append(record_fact(body, evidence_id=eid, locator="image:selected-panel", available=captured, observed=captured,
                               system=system, category=category, links=subject_links))
    if low:
        from dataclasses import replace
        checked=[]
        for fact in out:
            used={fact.resource.resource_id,str(fact.fields.get("email", ""))}
            uncertain=sorted(v for v in used if v and any(v in token or token.strip(".,:;()[]|") == v for token in low))
            checked.append(replace(fact,fields=dict(fact.fields,extraction_uncertain=True,uncertain_values=uncertain)) if uncertain else fact)
        out=checked
    return out, warnings
