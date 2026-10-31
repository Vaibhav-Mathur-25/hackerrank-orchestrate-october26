"""Independent snapshot/anonymization cases; no participant answer substitutions."""
import json
import unittest
from dataclasses import replace
from audit.extractors.csv_json import json_facts
from audit.identity import Subject
from audit.policy import cleaned


class DeclaredAnalyticsReportTest(unittest.TestCase):
    def fact(self,**changes):
        record={'resource_id':'opaque_metric','user_id':None,'email':None,'phone':None,'email_hash':None,
                'reporting_window':'last_30_days','metrics':{'sessions':3},'recent_activity':[]}
        record.update(changes)
        return json_facts(json.dumps({'source':'analytics_identity_store','collection':'customer_analytics_reports',
                          'captured_at':'2026-01-01T00:00:00Z','records':[record]}).encode(),'fixture_report','2026-01-01T00:00:00Z')[0]

    def test_explicit_null_report_schema_proves_anonymization_without_attribution(self):
        f=self.fact()
        self.assertIs(cleaned(f,Subject(user_id='person_fixture'),anonymous=True),True)
        self.assertEqual(f.links,())
        self.assertIn('name',f.coverage)

    def test_missing_identifier_column_is_not_a_null_readback(self):
        f=self.fact()
        f=replace(f,fields={k:v for k,v in f.fields.items() if k!='phone'},coverage=f.coverage-{'phone'})
        self.assertIsNone(cleaned(f,Subject(),anonymous=True))

    def test_remaining_name_hash_or_stable_identifier_prevents_anonymization(self):
        for values in [{'name':'Fixture Person'},{'email_hash':'d'*64},{'user_id':'person_fixture'}]:
            with self.subTest(values=values):self.assertIs(cleaned(self.fact(**values),Subject(),anonymous=True),False)

    def test_generic_partial_observation_does_not_inherit_report_schema(self):
        from audit.normalize import record_fact
        f=record_fact({'resource_id':'arbitrary','user_id':None,'email':None,'phone':None,'email_hash':None},
                      evidence_id='generic',locator='partial',available='2026-01-01T00:00:00Z',observed='2026-01-01T00:00:00Z',
                      system='analytics_platform',category='ANALYTICS_PROFILE')
        self.assertIsNone(cleaned(f,Subject(),anonymous=True))

class ProfileScopeQueryTest(unittest.TestCase):
    def scopes(self,replica_row=''):
        from audit.extractors.sql import sql_facts
        sql='''-- point-in-time database snapshot
BEGIN TRANSACTION;
CREATE TABLE customer_profiles_primary(resource_id TEXT,user_id TEXT,email TEXT);
CREATE TABLE customer_profiles_failover_replica(resource_id TEXT,user_id TEXT,email TEXT);
'''+replica_row+'\nCOMMIT;'
        return sql_facts(sql.encode(),'fixture_snapshot','2026-01-02T00:00:00Z')

    def subject(self):
        return Subject(user_id='user_fixture',aliases={'user_fixture','fixture@example.test'})

    def test_full_empty_primary_and_replica_keep_scope_absence_without_ids(self):
        from audit.discovery import profile_scope_queries
        from audit.planner import Auditor
        from fixtures import dataset,request
        facts=self.scopes();queries=profile_scope_queries(self.subject(),facts)
        self.assertEqual(len(queries),2)
        self.assertTrue(all(q['selector_result']=='NO_MATCH' and q['supports_selector_absence_at_cutoff'] for q in queries))
        result=Auditor(dataset(facts)).audit(request())
        self.assertEqual(result.inventory,[])
        self.assertIsNone(result.status)
        self.assertTrue(all(not q['supplies_former_resource_id'] for q in queries))
        self.assertEqual(profile_scope_queries(Subject(),facts),[])

    def test_replica_match_prevents_all_store_absence(self):
        from audit.discovery import profile_scope_queries
        for uid in ['user_fixture','opaque-key-without-id-prefix']:
            with self.subTest(uid=uid):
                facts=self.scopes("INSERT INTO customer_profiles_failover_replica VALUES('random_profile','"+uid+"',NULL);")
                queries=profile_scope_queries(Subject(user_id=uid),facts)
                self.assertEqual({q['selector_result'] for q in queries},{'NO_MATCH','MATCH'})
                self.assertFalse(all(q['supports_selector_absence_at_cutoff'] for q in queries))

    def test_partial_snapshot_and_sparse_identity_rows_do_not_prove_absence(self):
        from audit.discovery import profile_scope_queries
        facts=self.scopes("INSERT INTO customer_profiles_failover_replica VALUES('unknown_profile',NULL,NULL);")
        queries=profile_scope_queries(self.subject(),facts)
        self.assertEqual(next(q for q in queries if 'replica' in q['store'])['selector_result'],'UNKNOWN')
        partial=[replace(f,fields=dict(f.fields,complete=False)) if f.kind=='SCOPE' else f for f in facts]
        self.assertEqual(profile_scope_queries(self.subject(),partial),[])

    def test_later_restore_claim_blocks_cutoff_absence_but_future_claim_does_not(self):
        from audit.discovery import profile_scope_queries
        from audit.contracts import timestamp
        from fixtures import observed
        facts=self.scopes()
        claim=replace(observed('backup_service','archive','BACKUP_ARCHIVE',when='2026-01-03T00:00:00Z',links=()),kind='CLAIM',
                      fields={'event_type':'RESTORE_BACKUP','target_system':'account_service'})
        queries=profile_scope_queries(self.subject(),facts+[claim])
        self.assertTrue(all(not q['supports_selector_absence_at_cutoff'] for q in queries))
        # The production caller admits facts before querying, respecting both
        # observation and availability times, including future captures.
        cutoff=timestamp('2026-01-02T12:00:00Z')
        queries=profile_scope_queries(self.subject(),[f for f in facts+[claim] if f.admitted(cutoff)])
        self.assertTrue(all(q['supports_selector_absence_at_cutoff'] for q in queries))
        later=observed('account_service','new_profile','USER_PROFILE','PRESENT',when='2026-01-03T00:00:00Z',links=(),user_id='user_fixture')
        queries=profile_scope_queries(self.subject(),facts+[later])
        self.assertTrue(all(not q['supports_selector_absence_at_cutoff'] for q in queries))


if __name__=='__main__':unittest.main()
