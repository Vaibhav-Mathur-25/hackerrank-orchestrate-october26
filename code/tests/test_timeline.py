import unittest
from audit.contracts import Fact, Resource, timestamp
from audit.extractors.logs import log_facts
from audit.timeline import reconstruct

T = "2026-01-01T00:00:00Z"
R = Resource("account_service", "fixture_account")


def fact(state, when=T, available=None, store="primary", kind="OBSERVATION", **fields):
    return Fact("fixture_evidence", "fixture", timestamp(when), timestamp(available or when), R, "USER_PROFILE", kind, store, fields, (), state, frozenset(fields))


class TimelineTest(unittest.TestCase):
    def test_recreation_and_future_evidence(self):
        fs = [fact("ABSENT"), fact("PRESENT", "2026-01-02T00:00:00Z"), fact("ABSENT", "2026-01-03T00:00:00Z")]
        result = reconstruct(R, list(reversed(fs)), timestamp("2026-01-02T12:00:00Z"))
        self.assertEqual([f.state for f in result.observations], ["PRESENT"])

    def test_replica_not_erased_by_primary(self):
        result = reconstruct(R, [fact("ABSENT"), fact("PRESENT", store="replica")], timestamp(T))
        self.assertEqual({f.state for f in result.observations}, {"ABSENT", "PRESENT"})

    def test_claim_is_not_state(self):
        result = reconstruct(R, [fact("PRESENT"), fact("ABSENT", "2026-01-02T00:00:00Z", kind="CLAIM", event_type="DELETE_RECORD")], timestamp("2026-01-03T00:00:00Z"))
        self.assertEqual(result.observations[0].state, "PRESENT")
        self.assertIn("UNVERIFIED_TRANSITION", [i.code for i in result.issues])

    def test_equal_time_conflict(self):
        result = reconstruct(R, [fact("PRESENT"), fact("ABSENT")], timestamp(T))
        self.assertIn("STATE_CONFLICT", [i.code for i in result.issues])

    def test_partial_snapshot_cannot_erase_other_resources(self):
        from audit.extractors.csv_json import scope_fact
        scope=scope_fact("partial","table", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z", "account_service", "USER_PROFILE", "primary", [])
        result=reconstruct(R,[fact("PRESENT"),scope],timestamp("2026-01-03T00:00:00Z"))
        self.assertEqual(result.observations[0].state,"PRESENT")
        complete=scope_fact("full","table", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z", "account_service", "USER_PROFILE", "primary", [],True)
        result=reconstruct(R,[fact("PRESENT"),complete],timestamp("2026-01-03T00:00:00Z"))
        self.assertEqual(result.observations[0].state,"ABSENT")

    def test_trace_join_and_query_not_stored_pii(self):
        lines = '\n'.join([f'{T} level=DEBUG service=account_service trace_id=t event=profile_lookup_started lookup_key="person@example.test"', f'{T} level=INFO service=account_service trace_id=t event=profile_lookup_completed resource_id=a rows=0 http_status=404'])
        f = log_facts(lines.encode(), "file", T)[0]
        self.assertIn("person@example.test", f.links)
        self.assertNotIn("email", f.fields)
        self.assertEqual(f.state, "ABSENT")

    def test_all_log_encodings(self):
        cases = [
            '[INFO] [account_service] [t] profile_lookup_completed: resource_id="a" rows="0"',
            '| INFO | account_service | t | profile_lookup_completed | resource_id="a" rows="0"',
            '<14>1 node account_service t - - event="profile_lookup_completed" resource_id="a" rows="0"',
            '{"service":"account_service","event":"profile_lookup_completed","resource_id":"a","rows":"0"}',
            'requestId=t function=account_service message="event=\\"profile_lookup_completed\\" resource_id=\\"a\\" rows=\\"0\\""',
        ]
        for body in cases:
            with self.subTest(body=body): self.assertEqual(log_facts(f'{T} {body}'.encode(), "f", T)[0].state, "ABSENT")

    def test_failed_lookup_does_not_prove_absence(self):
        f=log_facts(f'{T} level=ERROR service=account_service event=profile_lookup_completed resource_id=a rows=0 http_status=500'.encode(),"f",T)[0]
        self.assertEqual(f.kind,"CLAIM")

    def test_equal_time_trace_input_order(self):
        start=f'{T} level=DEBUG service=account_service trace_id=t event=profile_lookup_started lookup_key="person@example.test"'
        finish=f'{T} level=INFO service=account_service trace_id=t event=profile_lookup_completed resource_id=a rows=0'
        a=log_facts((start+'\n'+finish).encode(),"f",T)[0]
        b=log_facts((finish+'\n'+start).encode(),"f",T)[0]
        self.assertEqual(a.links,b.links)

    def test_restore_claim_targets_downstream_resource_without_proving_presence(self):
        from audit.extractors.csv_json import activity_facts
        row={"activity_id":"restore_claim","event_time":"2026-01-02T00:00:00Z","event_type":"RESTORE_BACKUP",
             "source_system":"backup_service","target_system":"account_service","resource_id":"backup_fixture",
             "reported_result":"SUCCESS","details":"Restore job repopulated downstream resource fixture_account."}
        facts=activity_facts([row])
        r=reconstruct(R,[fact("ABSENT"),*facts],timestamp("2026-01-03T00:00:00Z"))
        self.assertEqual(r.observations[0].state,"ABSENT")
        self.assertIn("UNVERIFIED_TRANSITION",[i.code for i in r.issues])


if __name__ == "__main__": unittest.main()
