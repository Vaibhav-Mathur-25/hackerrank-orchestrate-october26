"""Join business document aliases through explicit catalog assertions, never filenames alone."""
from dataclasses import replace
import re
from .contracts import Fact, Resource


def corroborate_identifiers(facts):
    """Confirm exact low-confidence OCR tokens using independent catalog links.

    No character repair and no inferred state: the image remains the state
    source. The confirmation's later availability is preserved separately.
    """
    from .identity import identifier
    out=[]
    for fact in facts:
        uncertain=fact.fields.get('uncertain_values',[])
        if not fact.fields.get('extraction_uncertain') or not uncertain:continue
        links=[f for f in facts if f.kind=='LINK' and f.resource==fact.resource]
        matches=[]
        for link in links:
            supported={identifier(v) for v in link.links}|{link.resource.resource_id}
            if all(identifier(v) in supported for v in uncertain):matches.append(link)
        if not matches:continue
        link=min(matches,key=lambda f:(f.available,f.evidence_id))
        fields=dict(fact.fields,extraction_uncertain=False,ocr_corroboration=[link.evidence_id])
        out.append(replace(fact,available=max(fact.available,link.available),fields=fields))
    return out


def resource_links(facts: list[Fact]) -> list[Fact]:
    """Typed foreign keys establish attribution, never the target's state.

    Customer-search source_resource_id refers to the account being indexed.
    Other schemas must supply source_system explicitly; no ID-prefix guessing.
    Shared membership is not propagated to exclusive ownership.
    """
    out = []
    for fact in facts:
        if fact.kind != "OBSERVATION" or not fact.links:
            continue
        target = fact.fields.get("source_resource_id")
        system = fact.fields.get("source_system")
        category = ""
        if fact.category == "SEARCH_INDEX_ENTRY" and fact.resource.system == "search_service":
            system = system or "account_service"
            if system == "account_service": category = "USER_PROFILE"
        if not isinstance(target, str) or not target or not isinstance(system, str) or not system:
            continue
        out.append(replace(fact, resource=Resource(system, target), category=category,
                           kind="LINK", state="", coverage=frozenset(),
                           locator=fact.locator + "/source_resource_id",
                           fields={"relationship": "indexed_source", "via_resource": fact.resource.resource_id,
                                   "shared_subjects": fact.fields.get("shared_subjects", [])}))
    return out


def link_entities(facts: list[Fact]) -> list[Fact]:
    out=[]
    mappings=[]
    for fact in facts:
        if fact.kind!="LINK":continue
        aliases=re.findall(r"\(([^)]+)\)",str(fact.fields.get("details","")))
        for alias in aliases:mappings.append((alias,fact))
    for entity in facts:
        if entity.kind!="ENTITY":continue
        refs=set(entity.fields.get("document_refs",[]))
        for alias,link in mappings:
            if alias not in refs:continue
            # The catalog can name a public resource ID not printed in the
            # business artifact. Its relationship time must remain admissible.
            category=entity.category
            body=dict(entity.fields,relationship_evidence_id=link.evidence_id)
            if not category and "support-attachments" in str(body.get("text","")).lower():
                category="SUPPORT_ATTACHMENT"
            if not category:continue
            if "belongs only" in str(link.fields.get("details","")).lower():body["exclusive_subject"]=True
            out.append(replace(entity,resource=link.resource,category=category,kind="OBSERVATION",state="PRESENT",
                               available=max(entity.available,link.available),fields=body,
                               links=tuple(sorted(set(entity.links)|set(link.links))),coverage=frozenset(body)))
    return out
