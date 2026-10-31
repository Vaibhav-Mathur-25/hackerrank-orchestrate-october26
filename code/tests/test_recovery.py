"""Regression patterns recovered during forensic review; fictional IDs only."""
from dataclasses import replace
import json
import unittest
from audit.contracts import Resource, timestamp
from audit.entity_links import resource_links
from audit.extractors.csv_json import json_facts
from audit.extractors.logs import log_facts
from audit.extractors.sql import sql_facts
from audit.identity import IdentityGraph
from audit.timeline import reconstruct
from fixtures import PERSON, START, CUTOFF, observed
from fixtures import dataset, request
from audit.planner import Auditor
from audit.validate import validate_assessment


class RecoveryTest(unittest.TestCase):
    def test_foreign_key_recovers_account_but_not_presence_or_absence(self):
        row=observed('search_service','search_fixture','SEARCH_INDEX_ENTRY','PRESENT',
                     source_resource_id='account_fixture',email=PERSON['email'])
        links=resource_links([row])
        self.assertEqual(links[0].resource,Resource('account_service','account_fixture'))
        self.assertEqual(links[0].kind,'LINK')
        state=reconstruct(links[0].resource,[row,*links],timestamp(CUTOFF))
        self.assertEqual(state.category,'USER_PROFILE')
        self.assertIn('NO_STATE_OBSERVATION',[i.code for i in state.issues])
        self.assertFalse(resource_links([replace(row,category='UNDECLARED',resource=Resource('unknown','r'))]))

    def test_sql_foreign_key_and_conflicting_ownership(self):
        sql=b'''CREATE TABLE search_documents_primary(resource_id TEXT, email TEXT, source_resource_id TEXT);
        INSERT INTO search_documents_primary VALUES('search_fixture','fixture@example.test','account_fixture');'''
        fs=sql_facts(sql,'source',START);fs+=resource_links(fs)
        other=dict(PERSON,user_id='user_other',email='other@example.test',phone='+2',email_hash='d'*64)
        fs.append(observed(resource='account_fixture',links=('user_other',)))
        s=IdentityGraph([PERSON,other],[]).resolve(PERSON['email'],timestamp(CUTOFF),fs)
        self.assertIn('RESOURCE_OWNERSHIP_CONFLICT',[i.code for i in s.issues])

    def test_nested_query_is_link_only_and_future_link_stays_future(self):
        doc={'service_exports':{'account_service':{'profile_lookups':[
            {'resource_id':'account_fixture','observed_at':START,'status_code':404,'profile':None,
             'query':{'email':PERSON['email'],'neighbor':{'email':'other@example.test'}}}]}}}
        fs=json_facts(json.dumps(doc).encode(),'source',START)
        self.assertEqual(fs[0].links,(PERSON['email'],))
        self.assertNotIn('email',fs[0].fields)
        self.assertEqual(fs[0].state,'ABSENT')
        self.assertFalse(replace(fs[0],available=timestamp('2026-02-01T00:00:00Z')).admitted(timestamp(CUTOFF)))

    def test_trace_is_scoped_consumed_and_resource_checked(self):
        lines=[f'{START} service=account_service instance=a trace_id=t event=profile_lookup_started lookup_key={PERSON["email"]} resource_id=account_a',
               f'{START} service=account_service instance=b trace_id=t event=profile_lookup_completed resource_id=account_b rows=0',
               f'{START} service=account_service instance=a trace_id=t event=profile_lookup_completed resource_id=account_a rows=0',
               '2026-01-02T00:00:00Z service=account_service instance=a trace_id=t event=profile_lookup_completed resource_id=account_c rows=0']
        fs=log_facts('\n'.join(lines).encode(),'source','2026-01-02T00:00:00Z')
        links={f.resource.resource_id:f.links for f in fs}
        self.assertEqual(links['account_a'],(PERSON['email'],))
        self.assertEqual(links['account_b'],())
        self.assertEqual(links['account_c'],())
        reverse=log_facts('\n'.join(reversed(lines)).encode(),'source','2026-01-02T00:00:00Z')
        self.assertEqual(links,{f.resource.resource_id:f.links for f in reverse})

    def test_contact_index_is_not_an_attachment(self):
        data=f'{START} service=support_replica trace_id=t event=contact_query_started lookup_key={PERSON["email"]} source=legacy_contact_index\n{START} service=support_replica trace_id=t event=contact_query_completed resource_id=contact_fixture rows=1'
        f=log_facts(data.encode(),'source',START)[0]
        self.assertEqual(f.category,'SECONDARY_IDENTIFIER')
        self.assertEqual(f.links,(PERSON['email'],))

    def test_scan_key_phone_correlation(self):
        data=f'{START} service=support_platform trace_id=t event=attachment_scan_started scan_key="{PERSON["phone"]}"\n{START} service=support_platform trace_id=t event=attachment_pii_scan resource_id=attachment_fixture direct_identifiers=1'
        f=log_facts(data.encode(),'source',START)[0]
        self.assertIn(PERSON['phone'],f.links)

    def test_retention_amendment_does_not_reuse_older_longer_period(self):
        old=observed('security_service','audit_fixture','SECURITY_AUDIT_LOG','PRESENT',retention_until='2035-01-01T00:00:00Z')
        amended=replace(old,observed=timestamp('2026-01-02T00:00:00Z'),available=timestamp('2026-01-02T00:00:00Z'),
                        fields={'retention_until':'2026-01-03T00:00:00Z'})
        r=Auditor(dataset([observed(),old,amended])).audit(request())
        self.assertIn('EXPIRED_RETENTION_UNSPECIFIED',[i.code for i in r.issues])
        self.assertFalse(r.resolved)

    def test_retention_instrument_conflict_and_exact_boundary(self):
        old=observed('security_service','audit_fixture','SECURITY_AUDIT_LOG','PRESENT',retention_until=CUTOFF)
        r=Auditor(dataset([observed(),old])).audit(request())
        self.assertIn('EXPIRED_RETENTION_UNSPECIFIED',[i.code for i in r.issues])
        conflict=replace(old,fields={'retention_until':'2035-01-01T00:00:00Z'})
        r=Auditor(dataset([observed(),old,conflict])).audit(request())
        self.assertIn('RETENTION_INSTRUMENT_CONFLICT',[i.code for i in r.issues])

    def test_semantic_citation_wrong_state_same_id_rejected(self):
        r=Auditor(dataset()).audit(request())
        key=next(iter(r.proofs))
        r.proofs[key]=[replace(r.proofs[key][0],state='PRESENT')]
        with self.assertRaisesRegex(ValueError,'semantic proof'):
            validate_assessment(r,request().audit_at)

    def test_semantic_citation_non_exposure_rejected(self):
        dirty=observed('analytics_platform','analytics_fixture','ANALYTICS_PROFILE','PRESENT',email=PERSON['email'])
        r=Auditor(dataset([observed(),dirty])).audit(request())
        key=('analytics_platform','analytics_fixture','REPORT_EXPOSED_PII')
        r.proofs[key]=[replace(dirty,fields={},coverage=frozenset())]
        with self.assertRaisesRegex(ValueError,'semantic proof'):
            validate_assessment(r,request().audit_at)

    def test_semantic_policy_action_cannot_delete_retained_content(self):
        dirty=observed('support_platform','ticket_fixture','SUPPORT_MESSAGE','PRESENT',shared_context=True,email=PERSON['email'])
        r=Auditor(dataset([observed(),dirty])).audit(request())
        for step in r.steps:
            if step['phase']=='REMEDIATION': step.update(operation='DELETE_RECORD',state='ABSENT')
        with self.assertRaisesRegex(ValueError,'policy action'):
            validate_assessment(r,request().audit_at)

    def test_missing_remediation_for_one_of_two_violations_rejected(self):
        from audit.contracts import order_steps
        facts=[observed(state='PRESENT'),observed('search_service','search_fixture','SEARCH_INDEX_ENTRY','PRESENT')]
        r=Auditor(dataset(facts)).audit(request())
        r.steps=order_steps([s for s in r.steps if not(s['phase']=='REMEDIATION' and s['resource_id']=='search_fixture')])
        with self.assertRaisesRegex(ValueError,'coverage'):
            validate_assessment(r,request().audit_at)

    def test_complete_cannot_ignore_contradictory_replica_proof(self):
        r=Auditor(dataset()).audit(request())
        key=next(iter(r.proofs))
        r.proofs[key].append(replace(r.proofs[key][0],store='replica',state='PRESENT'))
        with self.assertRaisesRegex(ValueError,'another store'):
            validate_assessment(r,request().audit_at)

    def test_changing_only_success_claim_never_proves_state(self):
        obs=observed(state='PRESENT')
        claim=replace(obs,kind='CLAIM',observed=timestamp('2026-01-02T00:00:00Z'),available=timestamp('2026-01-02T00:00:00Z'),
                      fields={'event_type':'DELETE_RECORD','reported_result':'SUCCESS'},state='ABSENT')
        for result in ['SUCCESS','FAILED']:
            state=reconstruct(obs.resource,[obs,replace(claim,fields=dict(claim.fields,reported_result=result))],timestamp(CUTOFF))
            self.assertEqual([f.state for f in state.observations],['PRESENT'])
            self.assertIn('UNVERIFIED_TRANSITION',[i.code for i in state.issues])

    def test_anonymous_unlinked_records_cannot_be_assigned_by_row_order(self):
        account=observed()
        anonymous=observed('analytics_platform','unlinked','ANALYTICS_PROFILE','ANONYMIZED',links=(),user_id=None,email=None,phone=None,email_hash=None)
        graph=IdentityGraph([PERSON],[])
        a=graph.resolve(PERSON['email'],timestamp(CUTOFF),[account,anonymous])
        b=graph.resolve(PERSON['email'],timestamp(CUTOFF),[anonymous,account,anonymous])
        self.assertEqual(a.resources,b.resources)
        self.assertNotIn(anonymous.resource,a.resources)

    def test_redacted_profile_still_needs_whole_record_deletion(self):
        r=Auditor(dataset([observed(state='REDACTED')])).audit(request())
        self.assertTrue(r.resolved,r.issues)
        self.assertEqual(r.status,'INCOMPLETE')
        self.assertIn('DELETE_RECORD',[s['operation'] for s in r.steps])

    def test_partial_anonymization_readback_must_cover_name(self):
        partial=observed('analytics_platform','analytics_fixture','ANALYTICS_PROFILE','PRESENT',user_id=None,email=None,phone=None,email_hash=None)
        r=Auditor(dataset([observed(),partial])).audit(request())
        self.assertFalse(r.resolved)
        self.assertIn('STATE_FIELDS_INSUFFICIENT',[i.code for i in r.issues])

