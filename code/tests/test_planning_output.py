from dataclasses import replace
import random
import unittest
from audit.contracts import Fact, Resource, timestamp
from audit.planner import Auditor
from audit.serialize import csv_bytes
from audit.validate import validate_assessment
from fixtures import observed,dataset,request


class MetamorphicTest(unittest.TestCase):
    def baseline(self):
        return [observed(),observed("search_service","fixture_search","SEARCH_INDEX_ENTRY","PRESENT",email="fixture@example.test")]

    def encoded(self,facts):
        r=Auditor(dataset(facts)).audit(request())
        validate_assessment(r,request().audit_at)
        return csv_bytes([{"case_id":r.case_id,"deletion_status":r.status,"steps_json":r.steps}],{r.case_id})

    def test_order_irrelevance_and_future(self):
        base=self.baseline();expected=self.encoded(base)
        shuffled=list(reversed(base))
        self.assertEqual(expected,self.encoded(shuffled))
        unrelated=observed("search_service","another","SEARCH_INDEX_ENTRY","PRESENT",links=("someoneelse@example.test",),email="someoneelse@example.test")
        self.assertEqual(expected,self.encoded(base+[unrelated]))
        future=observed("search_service","fixture_search","SEARCH_INDEX_ENTRY","ABSENT",when="2026-01-10T00:00:00Z",available="2026-02-01T00:00:00Z")
        self.assertEqual(expected,self.encoded(base+[future]))
        self.assertEqual(expected,self.encoded(base+base))

    def test_wrong_citation_is_rejected(self):
        r=Auditor(dataset(self.baseline())).audit(request())
        r.steps[0]["evidence_id"]="invented"
        with self.assertRaises(ValueError):validate_assessment(r,request().audit_at)

    def test_explicit_order_conflict(self):
        account=observed(state="PRESENT",email="fixture@example.test",downstream_resources=[{"system_id":"search_service","resource_id":"fixture_search"}])
        r=Auditor(dataset([account,self.baseline()[1]])).audit(request())
        self.assertFalse(r.resolved)
        self.assertIn("ORDER_CONTRACT_CONFLICT",[i.code for i in r.issues])

    def test_future_ingestion_failure_has_no_effect(self):
        from audit.contracts import Issue
        data=dataset(self.baseline())
        data.issues=[Issue("INGESTION_FAILURE","ingestion","future unreadable file",evidence_ids=("future",))]
        data.artifacts=[{"file_id":"future","captured_at":"2026-02-01T00:00:00Z"}]
        r=Auditor(data).audit(request())
        self.assertTrue(r.resolved,r.issues)


if __name__ == "__main__":unittest.main()
