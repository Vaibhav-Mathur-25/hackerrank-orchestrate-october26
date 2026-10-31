import unittest
from fixtures import observed,dataset,request,PERSON
from audit.planner import Auditor


class VerificationRecoveryTest(unittest.TestCase):
    def test_attributed_redaction_preserves_record_without_asserting_shared_context(self):
        record=observed('support_platform','ticket','SUPPORT_MESSAGE','PRESENT',email=PERSON['email'])
        r=Auditor(dataset([observed(),record])).audit(request())
        self.assertTrue(r.resolved,r.issues)
        self.assertEqual(r.status,'INCOMPLETE')
        self.assertEqual([(s['phase'],s['operation']) for s in r.steps if s['resource_id']=='ticket'],[
            ('FINDING','REPORT_EXPOSED_PII'),('REMEDIATION','REDACT_RECORD'),('VERIFICATION','VERIFY_RECORD_REDACTED')])
        self.assertTrue(any(i.code=='SHARED_CONTEXT_UNPROVEN' and i.effect=='COMPLETE' for i in r.issues))

    def test_clean_support_record_without_condition_cannot_establish_complete(self):
        record=observed('support_platform','ticket','SUPPORT_MESSAGE','REDACTED',email=None,name=None,phone=None,email_hash=None)
        r=Auditor(dataset([observed(),record])).audit(request())
        self.assertFalse(r.resolved)
        self.assertNotEqual(r.status,'COMPLETE')

    def test_foreign_identifier_is_not_authorized_by_redaction_scope(self):
        record=observed('support_platform','ticket','SUPPORT_MESSAGE','PRESENT',email='other@example.test')
        r=Auditor(dataset([observed(),record])).audit(request())
        self.assertFalse(r.resolved)
        self.assertIn('RESOURCE_IDENTIFIER_CONFLICT',[i.code for i in r.issues])

    def test_known_current_checks_survive_missing_account_identity(self):
        record=observed('security_service','retained','SECURITY_AUDIT_LOG','PRESENT',retention_until='2028-01-01T00:00:00Z')
        r=Auditor(dataset([record])).audit(request())
        self.assertFalse(r.resolved)
        self.assertIsNone(r.status)
        self.assertEqual(len(r.verification_ledger),1)
        check=r.verification_ledger[0]
        self.assertTrue(check['current_state_supported'])
        self.assertEqual(check['current_check']['operation'],'VERIFY_RECORD_PRESENT')
        self.assertTrue(check['current_check']['evidence_id'])

    def test_state_proof_does_not_establish_unknown_retention_condition(self):
        record=observed('security_service','retained','SECURITY_AUDIT_LOG','PRESENT')
        r=Auditor(dataset([record])).audit(request())
        check=r.verification_ledger[0]
        self.assertTrue(check['current_state_supported'])
        self.assertIsNone(check['policy_compliant'])
        self.assertFalse(r.resolved)

    def test_future_target_is_not_presented_as_current_proof(self):
        r=Auditor(dataset([observed(state='PRESENT')])).audit(request())
        check=r.verification_ledger[0]
        self.assertFalse(check['current_state_supported'])
        self.assertIsNone(check['current_check'])
        self.assertEqual(check['planned_check']['operation'],'VERIFY_RECORD_ABSENT')
        self.assertEqual(check['planned_check']['evidence_id'],'')
