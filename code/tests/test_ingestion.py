import tempfile
from pathlib import Path
import unittest
from audit.inputs import Inputs
from audit.extractors.sql import sql_facts
from audit.extractors.csv_json import json_facts

T = "2026-01-01T00:00:00Z"


class IngestionTest(unittest.TestCase):
    def test_gold_and_traversal_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            reader = Inputs(Path(tmp))
            for p in ["sample_output.csv", "output.csv", "../sample_deletion_requests.csv"]:
                with self.assertRaises((PermissionError, ValueError)): reader.read(p)

    def test_sql_scope_and_replica(self):
        sql = b"CREATE TABLE customer_profiles_primary(resource_id TEXT,user_id TEXT,email TEXT); INSERT INTO customer_profiles_primary VALUES('a','u','x@example.test'); CREATE TABLE customer_profiles_failover_replica(resource_id TEXT,user_id TEXT,email TEXT);"
        facts = sql_facts(sql, "f", T)
        self.assertTrue(any(f.resource.resource_id == "a" and f.store == "primary" for f in facts))
        self.assertTrue(any(f.kind == "SCOPE" and f.store.endswith("replica") for f in facts))

    def test_sql_external_access_denied(self):
        with self.assertRaises(Exception): sql_facts(b"ATTACH DATABASE '/tmp/should-not-exist-audit' AS evil;", "f", T)
        self.assertFalse(Path('/tmp/should-not-exist-audit').exists())

    def test_json_declared_count(self):
        with self.assertRaises(ValueError): json_facts(b'{"record_count":1,"records":[]}', "f", T)

    def test_future_snapshot_not_backdated(self):
        data = b'{"snapshots":[{"captured_at":"2026-01-01T00:00:00Z","data_store":"account_service","collection":"customer_profiles","records":[]}]}'
        fact = json_facts(data, "f", "2026-02-01T00:00:00Z")[0]
        from audit.contracts import timestamp
        self.assertFalse(fact.admitted(timestamp(T)))

    def test_lookup_subject_is_not_a_stored_identifier(self):
        data=b'{"records":[{"system":"analytics_platform","resource_id":"r","record_type":"ANALYTICS_PROFILE","result":"ANONYMIZED","subject_reference":"user_fixture"}]}'
        fact=json_facts(data,"file",T)[0]
        self.assertIn("user_fixture",fact.links)
        self.assertNotIn("user_id",fact.fields)
        self.assertEqual(fact.state,"ANONYMIZED")

    def test_sql_booleans_normalized(self):
        sql=b"CREATE TABLE connector_subscriptions(resource_id TEXT,customer_reference TEXT,enabled INTEGER); INSERT INTO connector_subscriptions VALUES('f','user_fixture',1);"
        fact=next(f for f in sql_facts(sql,"file",T) if f.kind=="OBSERVATION")
        self.assertIs(fact.fields["enabled"],True)


if __name__ == "__main__": unittest.main()
