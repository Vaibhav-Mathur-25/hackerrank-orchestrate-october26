"""Behavioral acceptance tests for status, action and discovery independence."""
import unittest
from dataclasses import replace
from audit.planner import Auditor
from audit.validate import validate_assessment
from audit.contracts import order_steps
from fixtures import observed,dataset,request
from audit.contracts import timestamp,Resource
from audit.timeline import reconstruct
from audit.extractors.sql import sql_facts
from audit.extractors.csv_json import json_facts,scope_fact
from audit.extractors.logs import log_facts


class ReleaseCoverageTest(unittest.TestCase):
    def security(self):
        return observed('security_service','retained','SECURITY_AUDIT_LOG','PRESENT')

    def test_unknown_retention_preserved_in_independently_incomplete_plan(self):
        r=Auditor(dataset([observed(state='PRESENT'),self.security()])).audit(request())
        self.assertTrue(r.resolved,r.issues)
        self.assertEqual(r.status,'INCOMPLETE')
        self.assertIn(('retained','VERIFY_RECORD_PRESENT'),[(s['resource_id'],s['operation']) for s in r.steps])
        self.assertFalse(any(s['resource_id']=='retained' and s['phase']=='REMEDIATION' for s in r.steps))
        self.assertTrue(any(i.code=='RETENTION_CONDITION_UNKNOWN' and i.effect=='COMPLETE' for i in r.issues))
        validate_assessment(r,request().audit_at)

    def test_unknown_retention_cannot_support_complete(self):
        r=Auditor(dataset([observed(),self.security()])).audit(request())
        self.assertFalse(r.resolved)
        self.assertNotEqual(r.status,'COMPLETE')

    def test_missing_retained_record_still_blocks_incomplete(self):
        missing=replace(self.security(),state='ABSENT')
        r=Auditor(dataset([observed(state='PRESENT'),missing])).audit(request())
        self.assertFalse(r.resolved)
        self.assertEqual(r.status,'INCOMPLETE')

    def test_unassigned_anonymous_record_prevents_complete(self):
        account=observed()
        anonymous=replace(observed('analytics_platform','unassigned','ANALYTICS_PROFILE','ANONYMIZED',links=()),evidence_id=account.evidence_id)
        r=Auditor(dataset([account,anonymous])).audit(request())
        self.assertFalse(r.resolved)
        self.assertNotEqual(r.status,'COMPLETE')
        self.assertTrue(r.discovery['unassigned_resources'])

    def test_independent_coverage_catches_deleted_inventory_entry(self):
        extra=observed('search_service','known_search','SEARCH_INDEX_ENTRY','PRESENT')
        r=Auditor(dataset([observed(state='PRESENT'),extra])).audit(request())
        # Simulate a generator bug removing the same resource from its plan AND
        # its inventory. The independent source scan must still catch it.
        r.inventory=[i for i in r.inventory if i['resource_id']!='known_search']
        r.steps=order_steps([s for s in r.steps if s['resource_id']!='known_search'])
        with self.assertRaisesRegex(ValueError,'discovery'):
            validate_assessment(r,request().audit_at)

    def test_explicitly_restricted_request_does_not_require_account(self):
        attachment=observed('support_platform','file','SUPPORT_ATTACHMENT','PRESENT',exclusive_subject=True)
        r=Auditor(dataset([attachment])).audit(request('Delete only my attachment.'))
        self.assertTrue(r.resolved,r.issues)
        self.assertEqual(r.status,'INCOMPLETE')

    def test_full_table_dump_proves_absence_for_grounded_foreign_key(self):
        sql=b'''-- point-in-time database snapshot
        BEGIN TRANSACTION;
        CREATE TABLE customer_profiles_primary(resource_id TEXT,user_id TEXT);
        CREATE TABLE customer_profiles_failover_replica(resource_id TEXT,user_id TEXT);
        COMMIT;'''
        fs=sql_facts(sql,'snapshot','2026-01-02T00:00:00Z')
        link=replace(observed(resource='old_account'),kind='LINK',state='')
        state=reconstruct(link.resource,[link,*fs],request().audit_at)
        self.assertEqual({f.store for f in state.observations},{'primary','customer_profiles_failover_replica'})
        self.assertTrue(all(f.state=='ABSENT' for f in state.observations))

    def test_unscoped_empty_table_does_not_prove_absence(self):
        fs=sql_facts(b'CREATE TABLE customer_profiles(resource_id TEXT,user_id TEXT);','query','2026-01-02T00:00:00Z')
        self.assertFalse(any(f.fields.get('complete') for f in fs))
        state=reconstruct(observed().resource,[observed(state='PRESENT',store='primary'),*fs],request().audit_at)
        self.assertEqual([f.state for f in state.observations],['PRESENT'])

    def test_empty_json_requires_declared_collection_scope(self):
        import json
        doc={'snapshots':[{'data_store':'account_service','collection':'customer_profiles','captured_at':'2026-01-02T00:00:00Z','records':[]}]}
        f=json_facts(json.dumps(doc).encode(),'f','2026-01-02T00:00:00Z')[0]
        self.assertFalse(f.fields['complete'])
        doc['snapshots'][0]['scope']={'type':'full_collection'}
        f=json_facts(json.dumps(doc).encode(),'f','2026-01-02T00:00:00Z')[0]
        self.assertTrue(f.fields['complete'])

    def test_scope_does_not_invent_missing_retained_replica(self):
        record=self.security()
        scope=scope_fact('replica','table','2026-01-02T00:00:00Z','2026-01-02T00:00:00Z','security_service','SECURITY_AUDIT_LOG','unrelated_replica',[],True)
        state=reconstruct(record.resource,[record,scope],request().audit_at)
        self.assertEqual([f.state for f in state.observations],['PRESENT'])

    def test_delete_claim_preserves_absence_but_restore_claim_does_not(self):
        record=observed()
        later=replace(record,kind='CLAIM',observed=timestamp('2026-01-02T00:00:00Z'),available=timestamp('2026-01-02T00:00:00Z'),fields={'event_type':'DELETE_RECORD'})
        r=Auditor(dataset([record,later])).audit(request())
        self.assertTrue(r.resolved,r.issues)
        restored=replace(later,fields={'event_type':'RESTORE_BACKUP'})
        r=Auditor(dataset([record,restored])).audit(request())
        self.assertFalse(r.resolved)
        self.assertIn('UNVERIFIED_TRANSITION',[i.code for i in r.issues])

    def test_explicit_store_readback_updates_primary_and_preserves_replica(self):
        primary=observed(state='PRESENT',store='primary')
        replica=replace(primary,store='failover')
        text='2026-01-02T00:00:00Z service=account_service event=profile_lookup_completed resource_id=fixture_account rows=0 read_store=primary'
        readback=log_facts(text.encode(),'read','2026-01-02T00:00:00Z')[0]
        state=reconstruct(primary.resource,[primary,replica,readback],request().audit_at)
        self.assertEqual({(f.store,f.state) for f in state.observations},{('primary','ABSENT'),('failover','PRESENT')})

    def test_metadata_difference_is_not_state_conflict(self):
        a=observed(state='PRESENT',email='fixture@example.test',trace_id='trace_a')
        b=observed(state='PRESENT',email='fixture@example.test',trace_id='trace_b')
        r=Auditor(dataset([a,b])).audit(request())
        self.assertTrue(r.resolved,r.issues)

    def test_future_unassigned_record_does_not_block_earlier_complete(self):
        account=observed()
        extra=replace(observed('analytics_platform','unassigned','ANALYTICS_PROFILE','ANONYMIZED',links=()),evidence_id=account.evidence_id,
                      available=timestamp('2026-02-01T00:00:00Z'))
        self.assertTrue(Auditor(dataset([account,extra])).audit(request()).resolved)

    def test_scope_does_not_ignore_additional_account_deletion(self):
        attachment=observed('support_platform','file','SUPPORT_ATTACHMENT','PRESENT',exclusive_subject=True)
        r=Auditor(dataset([attachment])).audit(request('Delete only my attachment and delete my account.'))
        self.assertFalse(r.resolved)
        self.assertIn('ACCOUNT_COVERAGE_UNRESOLVED',[i.code for i in r.issues])

    def test_negated_scoped_deletion_does_not_authorize_actions(self):
        r=Auditor(dataset()).audit(request("Don't delete only my attachment."))
        self.assertEqual(r.status,'NOT_APPLICABLE')
        self.assertEqual(r.steps,[])

    def test_missing_independent_assessment_is_rejected(self):
        r=Auditor(dataset()).audit(request())
        r.discovery={}
        with self.assertRaisesRegex(ValueError,'discovery'):
            validate_assessment(r,request().audit_at)

    def test_full_plan_from_search_foreign_key_and_full_account_dump(self):
        from audit.entity_links import resource_links
        sql=b'''-- point-in-time database snapshot
        BEGIN TRANSACTION;
        CREATE TABLE customer_profiles(resource_id TEXT,user_id TEXT);
        COMMIT;'''
        search=observed('search_service','search_item','SEARCH_INDEX_ENTRY','PRESENT',source_resource_id='old_account')
        facts=[search,*resource_links([search]),*sql_facts(sql,'snapshot','2026-01-02T00:00:00Z')]
        result=Auditor(dataset(facts)).audit(request())
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual([(s['phase'],s['operation'],s['resource_id']) for s in result.steps],[
            ('FINDING','REPORT_REMAINING_RECORD','search_item'),
            ('REMEDIATION','DELETE_RECORD','search_item'),
            ('VERIFICATION','VERIFY_RECORD_ABSENT','old_account'),
            ('VERIFICATION','VERIFY_RECORD_ABSENT','search_item')])
        validate_assessment(result,request().audit_at)

