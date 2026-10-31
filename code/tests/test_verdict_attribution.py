"""A policy violation needs more than the existence of a disputed resource."""
from dataclasses import replace
import unittest
from audit.planner import Auditor
from audit.candidates import choose_candidate,choose_review_candidate,REVIEW_OWNER
from fixtures import observed,dataset,request


class VerdictAttributionTest(unittest.TestCase):
    def conflicting_profile(self):
        record=observed('marketing_platform','profile','MARKETING_PROFILE','PRESENT',links=('other@example.test',),email='other@example.test')
        link=replace(record,kind='LINK',evidence_id='catalog',links=('user_fixture',),fields={})
        return record,link

    def test_catalog_link_does_not_prove_foreign_profile_violation(self):
        result=Auditor(dataset(list(self.conflicting_profile()))).audit(request())
        self.assertIsNone(result.status)
        self.assertFalse(result.gates['verdict_supported'])
        self.assertIsNone(choose_candidate(result,request().audit_at).row)
        reviewed=choose_review_candidate(result,request().audit_at)
        self.assertEqual(reviewed.confidence,REVIEW_OWNER)
        self.assertFalse(reviewed.strict_released)
        self.assertTrue(any('DO NOT DELETE' in x for x in reviewed.execution_preconditions))

    def test_unproven_attachment_condition_is_not_a_proven_violation(self):
        attachment=observed('support_platform','attachment','SUPPORT_ATTACHMENT','PRESENT')
        result=Auditor(dataset([attachment])).audit(request())
        self.assertIsNone(result.status)
        self.assertFalse(result.gates['verdict_supported'])
        self.assertIn('EXCLUSIVE_OWNERSHIP_UNPROVEN',[i.code for i in result.issues])

    def test_independent_violation_survives_an_ownership_dispute(self):
        search=observed('search_service','search_item','SEARCH_INDEX_ENTRY','PRESENT')
        result=Auditor(dataset([search,*self.conflicting_profile()])).audit(request())
        self.assertEqual(result.status,'INCOMPLETE')
        c=choose_candidate(result,request().audit_at)
        self.assertEqual({s['resource_id'] for s in c.row['steps_json']},{'search_item'})
        self.assertIn('profile',c.excluded_resources)

    def test_exclusively_owned_attachment_keeps_supported_verdict(self):
        attachment=observed('support_platform','attachment','SUPPORT_ATTACHMENT','PRESENT',exclusive_subject=True)
        result=Auditor(dataset([attachment])).audit(request())
        self.assertEqual(result.status,'INCOMPLETE')
        self.assertTrue(result.gates['verdict_supported'])

if __name__=='__main__':unittest.main()
