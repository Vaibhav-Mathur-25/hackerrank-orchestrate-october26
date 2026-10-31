import unittest
from dataclasses import replace
from fixtures import observed,dataset,request,PERSON
from audit.planner import Auditor
from audit.candidates import choose_candidate,validate_candidate_steps
from audit.entity_links import corroborate_identifiers
from audit.timeline import reconstruct
from audit.contracts import timestamp


class CandidateTest(unittest.TestCase):
    def test_support_sql_schema_covers_nonexistent_hash_column(self):
        from audit.extractors.sql import sql_facts
        sql=b'''CREATE TABLE support_records(resource_id TEXT,customer_reference TEXT,requester_name TEXT,requester_email TEXT,requester_phone TEXT,message_excerpt TEXT);
        INSERT INTO support_records VALUES('ticket','user_fixture',NULL,NULL,NULL,'Order update');'''
        facts=sql_facts(sql,'source','2026-01-01T00:00:00Z')
        row=next(f for f in facts if f.kind=='OBSERVATION')
        self.assertIn('email_hash',row.coverage)
        result=Auditor(dataset([observed(),row])).audit(request())
        self.assertEqual(result.status,'COMPLETE')

    def test_selected_search_panel_uses_stable_reference_not_uncertain_email(self):
        from unittest.mock import patch
        from audit.extractors.documents import document_facts
        text='Search Console search_77 first@example.test second@example.test'
        panel='Raw document - search_77\ncustomer_reference user_fixture\nemail first@example.test\nActivity\nsearch_88 second@example.test'
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])),patch('audit.extractors.documents.selected_panel_text',return_value=(panel,['first@example.test'])):
            fs,_=document_facts(b'bytes','.png','image','2026-01-01T00:00:00Z')
        self.assertEqual(fs[0].links,('user_fixture',))
        self.assertFalse(fs[0].fields.get('extraction_uncertain',False))
        self.assertEqual(fs[0].resource.resource_id,'search_77')

    def test_proven_incomplete_survives_unknown_account_without_new_ids(self):
        record=observed('search_service','search_item','SEARCH_INDEX_ENTRY','PRESENT')
        result=Auditor(dataset([record])).audit(request())
        self.assertFalse(result.resolved)
        c=choose_candidate(result,request().audit_at)
        self.assertEqual(c.row['deletion_status'],'INCOMPLETE')
        self.assertFalse(c.plan_complete)
        self.assertEqual({s['resource_id'] for s in c.row['steps_json']},{'search_item'})

    def test_observed_scope_complete_is_explicitly_uncertain(self):
        record=observed('security_service','retained','SECURITY_AUDIT_LOG','PRESENT')
        result=Auditor(dataset([record])).audit(request())
        c=choose_candidate(result,request().audit_at)
        self.assertEqual(c.row['deletion_status'],'COMPLETE')
        self.assertEqual(c.confidence,'INFERRED_COMPLETE_OBSERVED_SCOPE')
        self.assertFalse(c.strict_released)
        self.assertFalse(result.resolved)

    def test_unknown_restore_policy_cannot_be_filled_with_blocked_state(self):
        record=observed('backup_service','archive','BACKUP_ARCHIVE','PRESENT')
        result=Auditor(dataset([record])).audit(request())
        self.assertIsNone(choose_candidate(result,request().audit_at).row)

    def test_unsafe_attachment_deletion_is_not_emitted(self):
        search=observed('search_service','search_item','SEARCH_INDEX_ENTRY','PRESENT')
        attachment=observed('support_platform','attachment','SUPPORT_ATTACHMENT','PRESENT')
        result=Auditor(dataset([search,attachment])).audit(request())
        c=choose_candidate(result,request().audit_at)
        self.assertNotIn('attachment',{s['resource_id'] for s in c.row['steps_json']})
        self.assertIn('attachment',c.excluded_resources)

    def test_ocr_confirmation_needs_exact_values_and_keeps_availability(self):
        image=observed('export_service','export_item','USER_EXPORT','PRESENT',email=PERSON['email'],extraction_uncertain=True,uncertain_values=[PERSON['email']])
        catalog=replace(image,kind='LINK',evidence_id='catalog',available=timestamp('2026-01-02T00:00:00Z'),observed=timestamp('2026-01-02T00:00:00Z'),fields={},links=(PERSON['email'],'user_fixture'))
        confirmed=corroborate_identifiers([image,catalog])
        self.assertEqual(len(confirmed),1)
        self.assertFalse(confirmed[0].admitted(image.observed))
        early=reconstruct(image.resource,[image,catalog,*confirmed],image.observed)
        self.assertIn('EXTRACTION_UNVERIFIED',[i.code for i in early.issues])
        late=reconstruct(image.resource,[image,catalog,*confirmed],request().audit_at)
        self.assertNotIn('EXTRACTION_UNVERIFIED',[i.code for i in late.issues])
        mismatch=replace(catalog,links=('other@example.test',))
        self.assertEqual(corroborate_identifiers([image,mismatch]),[])
