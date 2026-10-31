"""Qualified schema completion preserves uncertainty and execution gates."""
from dataclasses import replace
import unittest
from audit.planner import Auditor
from audit.candidates import choose_candidate,choose_review_candidate,validate_candidate_steps,REVIEW_OWNER,REVIEW_BACKUP
from fixtures import observed,dataset,request


class ConditionalReviewTest(unittest.TestCase):
    def test_retained_archive_presence_does_not_invent_restore_state(self):
        record=observed('backup_service','archive','BACKUP_ARCHIVE','PRESENT')
        link=replace(record,kind='LINK',evidence_id='catalog',fields={})
        result=Auditor(dataset([record,link])).audit(request())
        self.assertIsNone(choose_candidate(result,request().audit_at).row)
        reviewed=choose_review_candidate(result,request().audit_at)
        self.assertEqual(reviewed.confidence,REVIEW_BACKUP)
        self.assertEqual([s['operation'] for s in reviewed.row['steps_json']],['VERIFY_RECORD_PRESENT'])
        self.assertFalse(reviewed.strict_released)
        self.assertFalse(result.resolved)
        self.assertTrue(any('restore' in p.lower() for p in reviewed.execution_preconditions))

    def test_known_active_restore_cannot_use_unknown_restore_review(self):
        record=observed('backup_service','archive','BACKUP_ARCHIVE','ACTIVE',restore_allowed=True)
        link=replace(record,kind='LINK',evidence_id='catalog',fields={})
        result=Auditor(dataset([record,link])).audit(request())
        self.assertIsNone(choose_review_candidate(result,request().audit_at))

    def test_conflicting_marketing_plan_is_conditional_and_guarded(self):
        record=observed('marketing_platform','profile','MARKETING_PROFILE','PRESENT',links=('other@example.test',),
                        email='other@example.test',extraction_uncertain=True,uncertain_values=['other@example.test'])
        link=replace(record,kind='LINK',evidence_id='catalog',links=('user_fixture',),fields={})
        result=Auditor(dataset([record,link])).audit(request())
        reviewed=choose_review_candidate(result,request().audit_at)
        self.assertEqual(reviewed.confidence,REVIEW_OWNER)
        self.assertFalse(reviewed.plan_complete)
        self.assertTrue(any('DO NOT DELETE' in p for p in reviewed.execution_preconditions))
        steps=reviewed.row['steps_json']
        self.assertEqual([s['operation'] for s in steps],['REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT'])
        with self.assertRaises(ValueError):validate_candidate_steps(result,'INCOMPLETE',steps,request().audit_at)
        validate_candidate_steps(result,'INCOMPLETE',steps,request().audit_at,review=REVIEW_OWNER)

    def test_unreadable_resource_id_cannot_be_reviewed_as_presence(self):
        record=observed('marketing_platform','profile','MARKETING_PROFILE','PRESENT',links=('other@example.test',),
                        email='other@example.test',extraction_uncertain=True,uncertain_values=['profile'])
        link=replace(record,kind='LINK',evidence_id='catalog',links=('user_fixture',),fields={})
        result=Auditor(dataset([record,link])).audit(request())
        self.assertIsNone(choose_review_candidate(result,request().audit_at))
