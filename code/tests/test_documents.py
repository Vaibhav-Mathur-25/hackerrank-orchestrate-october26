from unittest.mock import patch
import unittest
from audit.extractors.documents import document_facts

T="2026-01-01T00:00:00Z"


class DocumentsTest(unittest.TestCase):
    def test_attachment_and_retention(self):
        text="DELIVERY CORRECTION ATTACHMENT support_77 belongs only to fixture@example.test"
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])):
            fs,issues=document_facts(b'bytes','.pdf','f',T)
        self.assertEqual(fs[0].category,'SUPPORT_ATTACHMENT')
        self.assertTrue(fs[0].fields['exclusive_subject'])
        text="COMPLIANCE JOURNAL audit_record_77 subject user_fixture retain until 25 Aug 2027 04 03 UTC"
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])):
            fs,issues=document_facts(b'bytes','.pdf','f',T)
        self.assertIn('2027-08-25T04:03',fs[0].fields['retention_until'])

    def test_multi_subject_screen_not_globally_joined(self):
        text="Search Console\nsearch_1 first@example.test\nsearch_2 second@example.test"
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])):
            fs,issues=document_facts(b'bytes','.png','f',T)
        self.assertEqual(len(fs),2)
        self.assertEqual(fs[0].links,('first@example.test',))
        self.assertNotIn('second@example.test',fs[0].links)

    def test_backup_encryption_is_not_a_restore_block(self):
        text="Vault Recovery Manager backup_77 backup_77 customer@example.test AES-256 Healthy"
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])):
            fs,issues=document_facts(b'bytes','.png','f',T)
        self.assertNotIn('restore_allowed',fs[0].fields)

    def test_explicit_catalog_alias_and_availability(self):
        from audit.contracts import Fact,Resource,timestamp
        from audit.entity_links import link_entities
        entity=Fact('pdf','page',timestamp(T),timestamp(T),Resource('export_service',''),'USER_EXPORT','ENTITY',
                    fields={'document_refs':['DOC-123'],'text':'Business statement'},links=('fixture@example.test',))
        link=Fact('catalog','row',timestamp('2026-01-02T00:00:00Z'),timestamp('2026-01-02T00:00:00Z'),Resource('export_service','export_77'),kind='LINK',
                  fields={'details':'Catalog linked export_77 (DOC-123) to fixture@example.test.'},links=('fixture@example.test',))
        joined=link_entities([entity,link])
        self.assertEqual(joined[0].resource.resource_id,'export_77')
        self.assertFalse(joined[0].admitted(timestamp(T)))
        unrelated=Fact('other','row',timestamp(T),timestamp(T),Resource('export_service','other'),kind='LINK',fields={'details':'Catalog linked other (DOC-999)'})
        self.assertEqual(link_entities([entity,unrelated]),[])

    def test_selected_panel_excludes_neighbor_and_history(self):
        text='BridgeOps data_flow_77 first@example.test data_flow_88 second@example.test'
        panel='data_flow_77\nSelector first@example.test\nSync mode Continuous sync\nActivity\ndata_flow_88 second@example.test'
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])), patch('audit.extractors.documents.selected_panel_text',return_value=(panel,[])):
            facts,_=document_facts(b'bytes','.png','f',T)
        self.assertEqual(len(facts),1)
        self.assertEqual(facts[0].links,('first@example.test',))
        self.assertIs(facts[0].fields['enabled'],True)

    def test_selected_panel_health_is_not_configuration(self):
        text='BridgeOps data_flow_77 first@example.test'
        panel='data_flow_77\nSelector first@example.test\nStatus Healthy\nActivity\nYesterday Disabled'
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])), patch('audit.extractors.documents.selected_panel_text',return_value=(panel,[])):
            facts,_=document_facts(b'bytes','.png','f',T)
        self.assertNotIn('enabled',facts[0].fields)

    def test_panel_critical_uncertainty_is_preserved(self):
        text='Customer Download export_77 first@example.test'
        panel='export_77\nOwner first@example.test'
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])), patch('audit.extractors.documents.selected_panel_text',return_value=(panel,['first@example.test'])):
            facts,_=document_facts(b'bytes','.png','f',T)
        self.assertTrue(facts[0].fields['extraction_uncertain'])

    def test_retention_register_rows_do_not_merge_customers(self):
        text='Register generated 01 Jan 2026 UTC\nORD-887 | user_fixture | Dispute | Retain until 04 May 2027\nORD-998 | user_other | Tax | Retain until 19 June 2028'
        with patch('audit.extractors.documents.extract_text',return_value=(text,[])):
            facts,_=document_facts(b'bytes','.pdf','f',T)
        self.assertEqual([f.links for f in facts],[('user_fixture',),('user_other',)])
        self.assertEqual(facts[0].fields['retention_until'],'2027-05-05T00:00:00+00:00')
        self.assertEqual(facts[1].fields['retention_until'],'2028-06-20T00:00:00+00:00')
        self.assertTrue(all(f.kind=='ENTITY' and not f.resource.resource_id for f in facts))


if __name__=='__main__':unittest.main()
