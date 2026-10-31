import unittest
from audit.planner import Auditor
from audit.validate import validate_assessment
from fixtures import observed, dataset, request, CUTOFF


class PolicyRiskIntegrationTest(unittest.TestCase):
    def audit(self, extra):
        return Auditor(dataset([observed(),*extra])).audit(request())

    def test_non_deletion_has_no_actions(self):
        result=Auditor(dataset()).audit(request("Stop promotional emails only; please don't delete my account."))
        self.assertTrue(result.resolved)
        self.assertEqual((result.status,result.steps),("NOT_APPLICABLE",[]))

    def test_shared_record_redaction_and_already_compliant_account(self):
        record=observed("support_platform","fixture_message","SUPPORT_MESSAGE","PRESENT",shared_context=True,email="fixture@example.test",text="Order shared with an agent")
        result=self.audit([record])
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"INCOMPLETE")
        ops=[s["operation"] for s in result.steps]
        self.assertIn("REDACT_RECORD",ops)
        self.assertIn("VERIFY_RECORD_ABSENT",ops)
        self.assertNotIn("DELETE_RECORD",ops)

    def test_tombstone_stable_reference_and_hash(self):
        clean=observed("identity_service","fixture_tombstone","ACCOUNT_TOMBSTONE","PRESENT",user_id="user_fixture",name=None,email=None,phone=None,email_hash=None,account_status="DELETED")
        result=self.audit([clean])
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"COMPLETE")
        dirty=observed("identity_service","fixture_tombstone","ACCOUNT_TOMBSTONE","PRESENT",user_id="user_fixture",name=None,email=None,phone=None,email_hash="c"*64,account_status="DELETED")
        result=self.audit([dirty])
        self.assertEqual(result.status,"INCOMPLETE")
        self.assertIn("REDACT_RECORD",[s["operation"] for s in result.steps])

    def test_backup_restore_and_flow_order(self):
        extras=[observed("backup_service","fixture_archive","BACKUP_ARCHIVE","PRESENT",restore_allowed=True),
                observed("integration_service","fixture_flow","DATA_FLOW","ACTIVE",enabled=True),
                observed("search_service","fixture_search","SEARCH_INDEX_ENTRY","PRESENT",email="fixture@example.test")]
        result=self.audit(extras)
        self.assertTrue(result.resolved,result.issues)
        actions=[s["operation"] for s in result.steps if s["phase"]=="REMEDIATION"]
        self.assertEqual(actions,["DISABLE_DATA_FLOW","BLOCK_RESTORE","DELETE_RECORD"])
        self.assertNotIn("DELETE_RECORD",[s["operation"] for s in result.steps if s["resource_id"]=="fixture_archive"])

    def test_blocked_backup_compliant(self):
        result=self.audit([observed("backup_service","fixture_archive","BACKUP_ARCHIVE","PRESENT",restore_allowed=False)])
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"COMPLETE")
        self.assertIn("VERIFY_RESTORE_BLOCKED",[s["operation"] for s in result.steps])

    def test_resurrection(self):
        present=observed(state="PRESENT",when="2026-01-20T00:00:00Z",email="fixture@example.test")
        future=observed(state="ABSENT",when="2026-02-01T00:00:00Z")
        result=self.audit([present,future])
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"INCOMPLETE")

    def test_retention_period_and_missing_required_record(self):
        retained=observed("security_service","fixture_audit","SECURITY_AUDIT_LOG","PRESENT",retention_until="2027-01-01T00:00:00Z",user_id="user_fixture")
        result=self.audit([retained]);self.assertTrue(result.resolved,result.issues)
        missing=observed("security_service","fixture_audit","SECURITY_AUDIT_LOG","ABSENT",retention_until="2027-01-01T00:00:00Z")
        result=self.audit([missing]);self.assertFalse(result.resolved)
        self.assertIn("RETAINED_RECORD_MISSING",[i.code for i in result.issues])
        unknown=observed("security_service","fixture_audit","SECURITY_AUDIT_LOG","PRESENT")
        result=self.audit([unknown]);self.assertFalse(result.resolved)
        self.assertIn("RETENTION_CONDITION_UNKNOWN",[i.code for i in result.issues])

    def test_anonymization_requires_unlinking(self):
        clean=observed("analytics_platform","fixture_analytics","ANALYTICS_PROFILE","PRESENT",user_id=None,name=None,email=None,phone=None,email_hash=None)
        result=self.audit([clean]);self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"COMPLETE")
        dirty=observed("analytics_platform","fixture_analytics","ANALYTICS_PROFILE","PRESENT",user_id="user_fixture",name=None,email=None,phone=None,email_hash=None)
        result=self.audit([dirty]);self.assertEqual(result.status,"INCOMPLETE")

    def test_exclusive_attachment(self):
        attachment=observed("support_platform","fixture_attachment","SUPPORT_ATTACHMENT","PRESENT",exclusive_subject=True)
        result=self.audit([attachment]);self.assertTrue(result.resolved,result.issues)
        self.assertIn("DELETE_RECORD",[s["operation"] for s in result.steps])
        ambiguous=observed("support_platform","fixture_attachment","SUPPORT_ATTACHMENT","PRESENT")
        self.assertFalse(self.audit([ambiguous]).resolved)

    def test_shared_customer_fields_preserved(self):
        record=observed("support_platform","shared","SUPPORT_MESSAGE","PRESENT",shared_context=True,
                        shared_subjects=["user_fixture","user_other"],field_subjects={"email":"user_other"},
                        name=None,email="other@example.test",phone=None,email_hash=None,text="[REDACTED]")
        result=self.audit([record])
        self.assertTrue(result.resolved,result.issues)
        self.assertEqual(result.status,"COMPLETE")

    def test_active_and_expired_legal_hold(self):
        held=observed("legal_service","hold","LEGAL_HOLD_RECORD","PRESENT",retention_until="2030-01-01T00:00:00Z")
        result=self.audit([held]);self.assertTrue(result.resolved,result.issues)
        self.assertIn("VERIFY_RECORD_PRESENT",[s["operation"] for s in result.steps])
        expired=observed("legal_service","hold","LEGAL_HOLD_RECORD","PRESENT",retention_until="2025-01-01T00:00:00Z")
        result=self.audit([expired]);self.assertFalse(result.resolved)
        self.assertIn("EXPIRED_RETENTION_UNSPECIFIED",[i.code for i in result.issues])
        released=observed("legal_service","hold","LEGAL_HOLD_RECORD","PRESENT",when="2026-01-10T00:00:00Z",hold_active=False,retention_until="2030-01-01T00:00:00Z")
        result=self.audit([held,released]);self.assertFalse(result.resolved)
        self.assertIn("INACTIVE_HOLD_UNSPECIFIED",[i.code for i in result.issues])

    def test_replica_and_conflict(self):
        replica=observed(state="PRESENT",store="failover",email="fixture@example.test")
        self.assertEqual(self.audit([replica]).status,"INCOMPLETE")
        contradictory=observed(state="PRESENT",email="fixture@example.test")
        self.assertFalse(self.audit([contradictory]).resolved)

    def test_other_policy_categories(self):
        for category in ["CACHE_ENTRY","MARKETING_PROFILE","SECONDARY_IDENTIFIER"]:
            r=self.audit([observed("fixture_service","item",category,"PRESENT")])
            self.assertTrue(r.resolved,r.issues)
            self.assertIn("DELETE_RECORD",[s["operation"] for s in r.steps])
        r=self.audit([observed("fixture_service","telemetry","PRODUCT_TELEMETRY","PRESENT",email="fixture@example.test")])
        self.assertTrue(r.resolved,r.issues)
        self.assertIn("ANONYMIZE_RECORD",[s["operation"] for s in r.steps])

    def test_delivery_email_redaction(self):
        dirty=observed("email_delivery_service","delivery","EMAIL_DELIVERY_LOG","PRESENT",email="fixture@example.test",name="Fixture Person")
        r=self.audit([dirty]);self.assertTrue(r.resolved,r.issues)
        self.assertIn("REDACT_RECORD",[s["operation"] for s in r.steps])
        clean=observed("email_delivery_service","delivery","EMAIL_DELIVERY_LOG","PRESENT",email=None,name="Fixture Person")
        r=self.audit([clean]);self.assertTrue(r.resolved,r.issues)
        self.assertEqual(r.status,"COMPLETE")


if __name__ == "__main__": unittest.main()
