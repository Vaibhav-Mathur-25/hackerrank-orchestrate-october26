import unittest
from audit.contracts import Fact, Resource, timestamp
from audit.identity import IdentityGraph
from audit.intent import classify

T = "2026-01-01T00:00:00Z"


class IdentityIntentTest(unittest.TestCase):
    def identities(self):
        return [{"user_id":"user_a", "name":"Shared Name", "email":"new@example.test", "phone":"+1 222", "email_hash":"a"*64,"updated_at":T},
                {"user_id":"user_b", "name":"Shared Name", "email":"new.jr@example.test", "phone":"+1 333", "email_hash":"b"*64,"updated_at":T}]

    def test_history_and_decoy(self):
        audit=[{"audit_id":"audit_x","user_id":"user_a","event_time":T,"field_name":"email","old_value":"old@example.test","new_value":"new@example.test"}]
        facts=[Fact("file", "line", timestamp(T), timestamp(T), Resource("support_platform","attachment"),"SUPPORT_ATTACHMENT",links=("old@example.test",)),
               Fact("decoy", "line", timestamp(T), timestamp(T), Resource("support_platform","other"),"SUPPORT_ATTACHMENT",links=("new.jr@example.test",))]
        result=IdentityGraph(self.identities(),audit).resolve("OLD@example.test",timestamp(T),facts)
        self.assertEqual(result.user_id,"user_a")
        self.assertEqual({r.resource_id for r in result.resources},{"attachment"})

    def test_conflicting_owners_not_merged(self):
        f=Fact("file","line",timestamp(T),timestamp(T),Resource("a","r"),links=("user_a","user_b"))
        result=IdentityGraph(self.identities(),[]).resolve("new@example.test",timestamp(T),[f])
        self.assertTrue(any(i.code=="IDENTITY_CONFLICT" for i in result.issues))

    def test_future_binding_rejected(self):
        result=IdentityGraph(self.identities(),[]).resolve("new@example.test",timestamp("2025-01-01T00:00:00Z"),[])
        self.assertFalse(result.user_id)

    def test_historical_hash_phone_and_intervals(self):
        audits=[{"audit_id":"p","user_id":"user_a","event_time":T,"field_name":"phone","old_value":"+1 (111)","new_value":"+1 222"},
                {"audit_id":"h","user_id":"user_a","event_time":T,"field_name":"email_hash","old_value":"d"*64,"new_value":"a"*64}]
        graph=IdentityGraph(self.identities(),audits)
        bindings,_=graph.bindings(timestamp(T))
        old=next(b for b in bindings if b.value=="+1111")
        self.assertIsNone(old.start)
        self.assertEqual(old.end,timestamp(T))
        for alias in ["+1 111","d"*64]:
            f=Fact("f","line",timestamp(T),timestamp(T),Resource("fixture","r"),links=(alias,))
            result=graph.resolve("new@example.test",timestamp(T),[f])
            self.assertIn(Resource("fixture","r"),result.resources)

    def test_intents(self):
        for t in ["Please delete my account.","このメールアドレスに関連するアカウントの完全な削除を依頼します。", "Solicito a exclusão permanente da conta."]:
            self.assertTrue(classify(t).authorized)
        for t in ["Please stop promotional emails only. I am not asking for deletion.","Please don't delete my account.","Please download my account information in a portable format.","Correct my surname without removing my records."]:
            self.assertFalse(classify(t).authorized)
        self.assertIsNone(classify("What should happen next?").authorized)
        self.assertTrue(classify("I changed the email on this account before deleting it. Check the old address even in systems that do not display the email.").authorized)
        self.assertTrue(classify("Please delete my account without removing legally held invoices.").authorized)
        self.assertIsNone(classify("Please delete my account and keep my account active.").authorized)


if __name__ == "__main__": unittest.main()
