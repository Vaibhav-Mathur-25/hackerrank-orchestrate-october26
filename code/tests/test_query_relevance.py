"""Request relevance never turns an old miss into an owned record."""
from dataclasses import replace
import unittest
from audit.identity import IdentityGraph
from audit.planner import Auditor
from audit.contracts import timestamp
from fixtures import observed,dataset,request,PERSON


class NegativeQueryRelevanceTest(unittest.TestCase):
    def old_probe(self):
        return observed('account_service','opaque_previous_query','USER_PROFILE','ABSENT',
                        when='2025-12-20T00:00:00Z',links=(PERSON['email'],),event='profile_lookup_completed',http_status=404)

    def resolve(self,facts):
        return IdentityGraph([PERSON],[]).resolve(PERSON['email'],request().audit_at,facts,request_start=request().requested_at)

    def test_old_negative_only_probe_does_not_create_current_owned_inventory(self):
        probe=self.old_probe()
        deletion=replace(probe,kind='CLAIM',links=(),observed=timestamp('2026-01-04T00:00:00Z'),
                         available=timestamp('2026-01-04T00:00:00Z'),fields={'event_type':'DELETE_RECORD'})
        result=Auditor(dataset([observed(),probe,deletion])).audit(request())
        self.assertEqual({x['resource_id'] for x in result.inventory},{'fixture_account'})
        self.assertEqual(result.discovery['excluded_historical_negative_queries'][0]['resource_id'],probe.resource.resource_id)
        self.assertEqual(len(result.steps),1)

    def test_current_request_negative_query_is_still_verified(self):
        probe=replace(self.old_probe(),observed=timestamp('2026-01-02T00:00:00Z'),available=timestamp('2026-01-02T00:00:00Z'))
        result=Auditor(dataset([observed(),probe])).audit(request())
        self.assertEqual({x['resource_id'] for x in result.inventory},{'fixture_account',probe.resource.resource_id})
        self.assertEqual(result.discovery['excluded_historical_negative_queries'],[])

    def test_historical_positive_membership_preserves_even_old_compliant_record(self):
        probe=self.old_probe()
        positive=replace(probe,evidence_id='earlier_present',state='PRESENT',observed=timestamp('2025-12-01T00:00:00Z'),available=timestamp('2025-12-01T00:00:00Z'))
        self.assertIn(probe.resource,self.resolve([positive,probe]).resources)
        result=Auditor(dataset([observed(),positive,probe])).audit(request())
        self.assertIn(probe.resource.resource_id,{x['resource_id'] for x in result.inventory})

    def test_catalog_relationship_preserves_old_probe_and_future_catalog_does_not(self):
        probe=self.old_probe();catalog=replace(probe,kind='LINK',evidence_id='catalog',fields={})
        self.assertIn(probe.resource,self.resolve([probe,catalog]).resources)
        future=replace(catalog,observed=timestamp('2026-02-02T00:00:00Z'),available=timestamp('2026-02-02T00:00:00Z'))
        self.assertNotIn(probe.resource,self.resolve([probe,future]).resources)

    def test_unattributed_recreation_claim_retains_the_lead(self):
        probe=self.old_probe()
        for event in ['CREATE_RECORD','UPDATE_RECORD','RESTORE_BACKUP','SYNC_RECORD']:
            with self.subTest(event=event):
                claim=replace(probe,kind='CLAIM',links=(),fields={'event_type':event},
                              observed=timestamp('2026-01-05T00:00:00Z'),available=timestamp('2026-01-05T00:00:00Z'))
                self.assertIn(probe.resource,self.resolve([probe,claim]).resources)
        flow=observed('integration_service','connector','DATA_FLOW','ACTIVE',
                      downstream_resources=[{'system_id':probe.resource.system,'resource_id':probe.resource.resource_id}])
        self.assertIn(probe.resource,self.resolve([probe,flow]).resources)

    def test_retained_categories_and_explicit_stable_reference_are_not_pruned(self):
        probe=self.old_probe()
        retained=replace(probe,category='SECURITY_AUDIT_LOG')
        self.assertIn(retained.resource,self.resolve([retained]).resources)
        explicit=replace(probe,fields=dict(probe.fields,user_id=PERSON['user_id']))
        self.assertIn(explicit.resource,self.resolve([explicit]).resources)

if __name__=='__main__':unittest.main()
