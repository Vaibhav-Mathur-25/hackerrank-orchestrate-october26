"""Gemini proposes source-field extractions; deterministic guards admit them.

No model-derived resource discovery, ownership, policy, absence, anonymization,
exclusive membership or deletion decisions. Accepted fields enrich the existing
observation, then the unchanged identity/timeline/policy/planner runs again.
"""
from __future__ import annotations
from dataclasses import dataclass,replace
from datetime import datetime,timedelta,timezone
from collections import Counter
from pathlib import Path
import hashlib,json,re
from .contracts import Resource,timestamp
from .identity import identifier
from .planner import Auditor
from .inputs import Inputs
from .extractors.documents import extract_text,selected_panel_text
from .normalize import tokens

CATEGORY_FIELDS={
 'DATA_FLOW':{'enabled'},'BACKUP_ARCHIVE':{'restore_allowed'},
 'SECURITY_AUDIT_LOG':{'retention_until'},'LEGAL_HOLD_RECORD':{'retention_until'},
 'SUPPORT_MESSAGE':{'email','phone','email_hash','user_id'},
 'EMAIL_DELIVERY_LOG':{'email'},'ANALYTICS_PROFILE':{'email','phone','email_hash','user_id'},
 'PRODUCT_TELEMETRY':{'email','phone','email_hash','user_id'},'ACCOUNT_TOMBSTONE':{'email','phone','email_hash'}}
CLAIM_KEYS={'evidence_id','unit_id','system_id','resource_id','category','observed_at','identifiers','fields','uncertainty'}
IDENTIFIER_FIELDS={'email','phone','email_hash','user_id'}
RISKY_CONTEXT=re.compile(r'\b(?:history|previously|formerly|requested|proposed|scheduled|workflow|reported|should|would|will|must|not\s+(?:enabled|disabled|blocked|allowed))\b',re.I)

@dataclass(frozen=True)
class Unit:
    index:int
    anchor:object
    text:str
    source_hash:str
    identifier_map:dict
    utc_declared:bool=False

    @property
    def unit_id(self):return hashlib.sha256((self.anchor.evidence_id+'\0'+self.anchor.locator+'\0'+self.text).encode()).hexdigest()[:24]
    def payload(self,cutoff):
        f=self.anchor
        return {'evidence_id':f.evidence_id,'unit_id':self.unit_id,'system_id':f.resource.system,'resource_id':f.resource.resource_id,
                'category':f.category,'observed_at':f.observed.isoformat(),'available_at':f.available.isoformat(),
                'audit_at':cutoff.isoformat(),'source_sha256':self.source_hash,'source_locator':f.locator,
                'utc_declared':self.utc_declared,'allowed_fields':sorted(CATEGORY_FIELDS[f.category]),'source_text':self.text}


def redact(text,identities,audits):
    """Local reversible pseudonyms. No mapping goes to API, cache or telemetry."""
    values={v for row in identities for k,v in row.items() if k in {'name','email','phone','email_hash','user_id'} and v}
    values.update(v for row in audits for k,v in row.items() if k in {'old_value','new_value','user_id'} and v)
    values.update(tokens(text))
    values.update(re.findall(r'\+\d[\d ()-]{7,}\d',text))
    # Replace exact known values, longest first, in a single pass. Delimiters
    # prevent substring alias collisions. Maps are local to this source unit.
    values=sorted((v for v in values if len(v)>2 and v in text),key=lambda v:(-len(v),v))
    if not values:return text,{}
    mapping={f'<IDENTIFIER_{i}>':v for i,v in enumerate(values)}
    forward={v:k for k,v in mapping.items()}
    pattern=re.compile('|'.join(re.escape(v) for v in values))
    return pattern.sub(lambda m:forward[m[0]],text),mapping


def retention_value(quote,utc_declared):
    match=re.fullmatch(r'\s*retain(?:ed)?\s+until\s*[:=]?\s*(.*?)\s*',quote,re.I)
    if not match:raise ValueError('retention_label')
    raw=match[1].strip()
    try:
        if re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+]00:00)',raw):return timestamp(raw).isoformat()
        if not utc_declared:raise ValueError('timezone_unknown')
        raw=re.sub(r'\s+UTC$','',raw,flags=re.I)
        for fmt in ['%Y-%m-%d','%d %b %Y','%d %B %Y','%d %b %Y %H:%M','%d %B %Y %H:%M']:
            try:
                value=datetime.strptime(raw,fmt).replace(tzinfo=timezone.utc)
                if '%H' not in fmt:value+=timedelta(days=1)
                return value.isoformat()
            except ValueError:pass
    except (ValueError,TypeError):pass
    raise ValueError('retention_date')


def grounded_value(field,quote,unit,subject):
    """Small typed source checkers, not an LLM semantic-confidence threshold."""
    if not isinstance(quote,str) or not 1<=len(quote)<=500 or quote not in unit.text:raise ValueError('quote_not_in_source')
    if RISKY_CONTEXT.search(quote):raise ValueError('claim_or_historical_quote')
    if quote.strip() not in {line.strip() for line in unit.text.splitlines()}:raise ValueError('quote_not_complete_source_line')
    if field=='enabled':
        m=re.fullmatch(r'\s*(?:sync\s+mode|synchronization|enabled)\s*[:=]?\s*(continuous\s+sync|enabled|disabled|true|false)\s*',quote,re.I)
        if not m:raise ValueError('sync_predicate')
        return m[1].lower() not in {'disabled','false'}
    if field=='restore_allowed':
        m=re.fullmatch(r'\s*(?:restore\s+(?:access|permission|allowed)|restore_allowed)\s*[:=]?\s*(blocked|denied|disabled|allowed|enabled|true|false)\s*',quote,re.I)
        if not m:raise ValueError('restore_predicate')
        return m[1].lower() in {'allowed','enabled','true'}
    if field=='retention_until':return retention_value(quote,unit.utc_declared)
    labels={'email':r'(?:email|owner\s+email|customer\s+email)','phone':r'(?:phone|customer\s+phone)',
            'email_hash':r'(?:email_hash|email\s+hash)','user_id':r'(?:user_id|customer_reference|subject\s+reference)'}
    if field not in labels:raise ValueError('field_not_allowed')
    m=re.fullmatch(r'\s*'+labels[field]+r'\s*[:=]?\s*(<IDENTIFIER_\d+>)\s*',quote,re.I)
    if not m or m[1] not in unit.identifier_map:raise ValueError('identifier_label')
    value=unit.identifier_map[m[1]]
    if identifier(value) not in subject.aliases:raise ValueError('foreign_identifier')
    if field=='email' and '@' not in value:raise ValueError('identifier_type')
    if field=='phone' and not value.startswith('+'):raise ValueError('identifier_type')
    if field=='email_hash' and not re.fullmatch(r'[a-fA-F0-9]{64}',value):raise ValueError('identifier_type')
    if field=='user_id' and value!=subject.user_id:raise ValueError('identifier_type')
    return value


def validate_response(response,unit,subject,cutoff):
    """Returns a replacement source observation, plus metadata-only decisions."""
    decisions=[];updates={};provenance={};f=unit.anchor
    def rejected(reason):decisions.append({'decision':'rejected','reason':reason})
    if not isinstance(response,dict) or set(response)!={'findings','uncertainty'} or not isinstance(response['findings'],list) or len(response['findings'])>8 or not isinstance(response['uncertainty'],list):
        rejected('response_schema');return f,decisions
    if response['uncertainty']:
        rejected('response_uncertainty');return f,decisions
    if not subject.user_id or f.resource not in subject.resources or not any(identifier(v) in subject.aliases for v in f.links) or not f.admitted(cutoff) or f.kind!='OBSERVATION' or f.state=='ABSENT' or f.fields.get('extraction_uncertain'):
        rejected('inadmissible_anchor');return f,decisions
    if any(i.blocking and i.component=='identity' and (not i.resource_id or i.resource_id==f.resource.resource_id) for i in subject.issues):
        rejected('identity_conflict');return f,decisions
    expected=unit.payload(cutoff)
    for claim in response['findings']:
        if not isinstance(claim,dict) or set(claim)!=CLAIM_KEYS:
            rejected('finding_schema');continue
        if any(claim[k]!=expected[k] for k in ['evidence_id','unit_id','system_id','resource_id','category','observed_at']):
            rejected('anchor_mismatch');continue
        if not isinstance(claim['uncertainty'],list) or claim['uncertainty']:
            rejected('finding_uncertainty');continue
        if not isinstance(claim['identifiers'],list) or any(not isinstance(v,str) or v not in unit.identifier_map or identifier(unit.identifier_map[v]) not in subject.aliases for v in claim['identifiers']):
            rejected('ungrounded_identifier');continue
        if not isinstance(claim['fields'],list) or not 1<=len(claim['fields'])<=8:
            rejected('field_schema');continue
        staged={};valid=True
        for field in claim['fields']:
            try:
                if not isinstance(field,dict) or set(field)!={'name','value_json','quote'}:raise ValueError('field_schema')
                name=field['name']
                if not isinstance(name,str) or name not in CATEGORY_FIELDS.get(f.category,set()):raise ValueError('field_not_allowed')
                if not isinstance(field['value_json'],str) or len(field['value_json'])>500:raise ValueError('value_schema')
                proposed=json.loads(field['value_json'])
                value=grounded_value(name,field['quote'],unit,subject)
                if name in IDENTIFIER_FIELDS:
                    proposed=unit.identifier_map.get(proposed) if isinstance(proposed,str) else None
                if type(value) is not type(proposed) or value!=proposed:raise ValueError('value_not_supported')
                for fields in (f.fields,staged,updates):
                    if name in fields and (type(fields[name]) is not type(value) or fields[name]!=value):raise ValueError('conflicting_field')
                staged[name]=value
            except (ValueError,TypeError,KeyError):
                rejected('invalid_field_grounding');valid=False;break
        if valid:
            for field in claim['fields']:
                provenance[field['name']]={'evidence_id':f.evidence_id,'locator':f.locator,'source_sha256':unit.source_hash,
                                          'unit_id':unit.unit_id,'quote_sha256':hashlib.sha256(field['quote'].encode()).hexdigest(),
                                          'masked_span_start':unit.text.find(field['quote']),'masked_span_length':len(field['quote'])}
            new=bool(set(staged)-set(f.fields)-set(updates));updates.update(staged)
            decisions.append({'decision':'accepted_new' if new else 'accepted_redundant','field_names':sorted(staged)})
    if not set(updates)-set(f.fields):return f,decisions
    return replace(f,fields=dict(f.fields,**updates,ai_provenance=provenance),coverage=f.coverage|frozenset(updates)),decisions


class AssistedAuditor:
    """Optional second pass; baseline runs first and remains immutable."""
    def __init__(self,dataset,root,client,cache=None):
        self.dataset=dataset;self.root=Path(root);self.client=client;self.cache=cache;self.base=Auditor(dataset)
        self.by_file={a['file_id']:a for a in dataset.artifacts};self.resource_ids={f.resource.resource_id for f in dataset.facts if f.resource.resource_id};self.text_cache={};self.decisions=[];self.changed_cases=[];self.eligible_units=0;self.source_unit_errors=0

    def units(self,request,subject,resources=None):
        for i,f in enumerate(self.dataset.facts):
            if resources is not None and f.resource not in resources:continue
            if f.resource not in subject.resources or f.kind!='OBSERVATION' or f.state=='ABSENT' or f.category not in CATEGORY_FIELDS or not f.admitted(request.audit_at) or f.fields.get('extraction_uncertain'):continue
            if not any(identifier(x) in subject.aliases for x in f.links):continue
            if CATEGORY_FIELDS[f.category]<=set(f.fields):continue
            a=self.by_file.get(f.evidence_id)
            if not a or a.get('status')!='parsed' or Path(a['file_path']).suffix not in {'.pdf','.png','.txt'}:continue
            key=(f.evidence_id,f.locator,f.resource,subject.user_id)
            if key not in self.text_cache:
                try:
                    raw=Inputs(self.root).read(a['file_path'],evidence=True)
                    if hashlib.sha256(raw).hexdigest()!=a['sha256']:continue
                    suffix=Path(a['file_path']).suffix
                    if f.locator.startswith('image:detail-panel'):
                        text,low=selected_panel_text(raw,self.cache);text=re.split(r'\bActivity\b',text,flags=re.I)[0]
                    else:
                        text,low=extract_text(raw,suffix,self.cache)
                        if f.locator.startswith(('ocr-line:','line:')):text=text.splitlines()[int(f.locator.split(':')[1])-1]
                    # A unit cannot merge rows or infer which of several resources
                    # a selector belongs to. Missing IDs are not supplied by AI.
                    rids=set(re.findall(r'\b[A-Za-z][A-Za-z0-9_]*\b',text)) & self.resource_ids
                    if rids!={f.resource.resource_id} or len(text)>6000 or low:continue
                    if re.search(r'\b(?:history|historical|workflow)\b',text,re.I):continue
                    if not re.search(r'(?<!\w)'+re.escape(f.resource.resource_id)+r'(?!\w)',text):continue
                    masked,mapping=redact(text,self.dataset.identities,self.dataset.audits)
                    # Names cannot establish membership, but conflicting typed
                    # identifiers in a selected unit require separate review.
                    typed=set(tokens(text))
                    if any(identifier(v) not in subject.aliases for v in typed):continue
                    self.text_cache[key]=(masked,mapping,'UTC' in text)
                except Exception:
                    self.source_unit_errors+=1;continue
            text,mapping,utc=self.text_cache[key]
            yield Unit(i,f,text,a['sha256'],mapping,utc)

    def audit(self,request):
        baseline=self.base.audit(request)
        # AI cannot rescue an unsafe identity or a non-deletion request.
        if not baseline.subject_id or baseline.status=='NOT_APPLICABLE':return baseline
        subject=self.base.identity.resolve(request.email,request.audit_at,self.dataset.facts,request_start=request.requested_at)
        if any(i.blocking and i.component=='identity' for i in subject.issues):return baseline
        targets={Resource(x['system_id'],x['resource_id']) for x in baseline.inventory if x['compliant'] is None}
        if not targets:return baseline
        changed={}
        for n,unit in enumerate(self.units(request,subject,targets)):
            if n>=2:break
            self.eligible_units+=1
            response=self.client.interpret(unit.payload(request.audit_at))
            if response is None:continue
            replacement,decisions=validate_response(response,unit,subject,request.audit_at)
            for d in decisions:self.decisions.append(dict(d,case_id=request.case_id,evidence_id=unit.anchor.evidence_id,unit_id=unit.unit_id))
            if replacement!=unit.anchor:changed[unit.index]=replacement
        if not changed:return baseline
        facts=[changed.get(i,f) for i,f in enumerate(self.dataset.facts)]
        candidate=Auditor(replace(self.dataset,facts=facts)).audit(request)
        # Preserve every existing source-backed step; additions must pass the
        # normal safety gates. In particular this cannot add a new ambiguous
        # destructive action to a best-effort partial plan.
        old={json.dumps(dict(s,step_no=0),sort_keys=True) for s in baseline.steps}
        new={json.dumps(dict(s,step_no=0),sort_keys=True) for s in candidate.steps}
        identity_or_policy=any(i.blocking and i.component in {'identity','policy'} and i.effect!='ADVISORY' for i in candidate.issues)
        if not old<=new or identity_or_policy or (baseline.resolved and not candidate.resolved):
            self.decisions.append({'case_id':request.case_id,'decision':'candidate_rejected','reason':'preservation_or_policy_gate'});return baseline
        if baseline.status!=candidate.status or baseline.steps!=candidate.steps or baseline.resolved!=candidate.resolved:self.changed_cases.append(request.case_id)
        return candidate

    def report(self):
        counts=Counter(d['decision'] for d in self.decisions)
        return dict(self.client.report(),eligible_units=self.eligible_units,source_unit_errors=self.source_unit_errors,accepted_new_findings=counts['accepted_new'],accepted_redundant_findings=counts['accepted_redundant'],
                    rejected_findings=counts['rejected'],rejected_case_candidates=counts['candidate_rejected'],changed_cases=self.changed_cases,
                    decisions=self.decisions,live_response_received=any(c['status']=='success' for c in self.client.calls),
                    live_workflow_validation_pending=not (counts['accepted_new'] and self.changed_cases and any(c['status']=='success' for c in self.client.calls)))
