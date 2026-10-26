"""Gig worker API workflow and access control checks using isolated SQLite fixtures."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time, timedelta, timezone
import os
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient
from api import db, settings
import api.main as service
from api.security import password_hash

# Isolated SQLite test fixture only. This deliberately fake reference never comes
# from Aadhaar or an identity provider and is never used by a production database.
DEV_IDENTITY_FIXTURE = "DEV-ONLY SYNTHETIC FIXTURE - NOT REAL AADHAAR"

class GigWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir=Path(__file__).resolve().parents[1]/'data'/'test-databases'
        self.temp_dir.mkdir(parents=True,exist_ok=True)
        self.database_path=self.temp_dir/f'test-gig-{os.getpid()}-{id(self)}.db'
        settings.DATABASE_URL='sqlite:///'+str(self.database_path)
        settings.APP_SECRET='test-only-secret-with-over-32-characters-0001'
        settings.APP_ENV='test'
        settings.INTEGRATION_KEY='test-integration-key'
        self.clock=datetime.combine(date.today(),time(9,20),ZoneInfo('Asia/Kolkata')).astimezone(timezone.utc)
        service.now=lambda:self.clock
        service.encrypt=lambda value:value
        service.decrypt=lambda value:value
        db.migrate()
        self.client=TestClient(service.app)
        self.operator_id='operator-test-id'
        with db.transaction() as conn:
            conn.execute("INSERT INTO users(id,email,password_hash,role,created_at) VALUES(?,?,?,'operator',?)",(self.operator_id,'operator@test.invalid',password_hash('Operator-test-password-473!'),service.stamp()))

    def tearDown(self):
        self.client.close()
        for suffix in ('','-wal','-shm'):
            path=Path(str(self.database_path)+suffix)
            if path.exists():path.unlink()

    def login(self,client,email,password):
        response=client.post('/api/auth/login',json={'email':email,'password':password})
        self.assertEqual(response.status_code,200,response.text)
        client.headers.update({'X-CSRF-Token':response.json()['csrf_token']})
        return response.json()['user']['id']

    def register_worker(self,email,client=None,identity_mode='authorized_provider'):
        client=client or self.client
        response=client.post('/api/auth/register',json={'email':email,'password':'Secure-test-password-491!','role':'contributor','phone':'+9198765432'+('11' if email.startswith('first') else '22' if email.startswith('second') else '10')})
        self.assertEqual(response.status_code,201,response.text)
        self.login(client,email,'Secure-test-password-491!')
        onboarding=client.post('/api/contributor/onboarding',json={
            'display_name':email.split('@')[0].title(),'address':'42 Worker Home Street, Bengaluru','date_of_birth':'1988-04-12','profession':'Care assistant',
            'identity_document_type':'Authorized Aadhaar provider reference','identity_mode':identity_mode,
            'identity_reference':DEV_IDENTITY_FIXTURE,'identity_consent':True,'city':'Bengaluru',
            'service_area':'Jayanagar','languages':['Kannada'],'tasks':['companionship']})
        self.assertEqual(onboarding.status_code,201,onboarding.text)
        return response.json()['id']

    def review_worker(self,worker_id,client=None,**changes):
        client=client or self.client
        self.login(client,'operator@test.invalid','Operator-test-password-473!')
        return client.patch(f'/api/admin/contributors/{worker_id}',json=changes)

    def create_gig(self,client=None,title='Companion walk',assigned_worker_id=None):
        client=client or self.client
        day=(service.india_now().date()+timedelta(days=1)).isoformat()
        response=client.post('/api/admin/gigs',json={
            'title':title,'description':'A short supervised walk in the neighbourhood.',
            'client_name':'Test Elder','client_phone':'+919811122233','client_address':'12 Sample Road, Jayanagar, Bengaluru',
            'contact_name':'Care contact','contact_phone':'+919822233344','city':'Bengaluru','service_area':'Jayanagar',
            'category':'Companionship','service_date':day,'start_time':'10:00','duration_hours':1,
            'fare_inr':300,'offered_payout_inr':240,'language':'Kannada','instructions':'Meet at the front entrance.',
            'required_skills':['companionship'],'priority':'standard','helpers_needed':1,'assigned_worker_id':assigned_worker_id,'consent_confirmed':True})
        self.assertEqual(response.status_code,201,response.text)
        return response.json()

    def test_roles_registration_training_and_sandbox_boundaries(self):
        self.assertEqual(self.client.post('/api/auth/register',json={'email':'legacy@test.invalid','password':'Secure-test-password-491!','role':'family'}).status_code,403)
        phone_only=self.client.post('/api/auth/register',json={'email':None,'password':'Secure-test-password-491!','role':'contributor','phone':'+919811122233'})
        self.assertEqual(phone_only.status_code,201,phone_only.text)
        self.assertEqual(self.client.post('/api/auth/login',json={'email':'+919811122233','password':'Secure-test-password-491!'}).status_code,200)
        worker=self.register_worker('sandbox@test.invalid',identity_mode='development_sandbox')
        self.assertEqual(self.client.post('/api/contributor/training/complete',json=['answers']).status_code,403)
        denied=self.review_worker(worker,identity_state='approved')
        self.assertEqual(denied.status_code,409,denied.text)
        self.client.post('/api/auth/logout')
        self.login(self.client,'sandbox@test.invalid','Secure-test-password-491!')
        profile=self.client.get('/api/contributor').json()
        self.assertFalse(profile['can_accept_gigs'])
        self.assertTrue(any('sandbox' in reason.lower() for reason in profile['ineligibility_reasons']))
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,403)

    def test_identity_approval_and_training_are_independent_eligibility_gates(self):
        worker=self.register_worker('gates@test.invalid')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,403)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        gig=self.create_gig(title='Onboarding gate check')
        self.client.post('/api/auth/logout')
        self.login(self.client,'gates@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.post(f"/api/bookings/{gig['id']}/accept",json={}).status_code,403)
        self.client.post('/api/auth/logout')
        self.review_worker(worker,identity_state='approved')
        self.client.post('/api/auth/logout')
        self.login(self.client,'gates@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,403)
        self.client.post('/api/auth/logout')
        self.review_worker(worker,approval_state='approved')
        self.client.post('/api/auth/logout')
        self.login(self.client,'gates@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,403)
        self.client.post('/api/auth/logout')
        self.review_worker(worker,training_complete=True)
        self.client.post('/api/auth/logout')
        self.login(self.client,'gates@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,200)

    def test_admin_publishes_worker_accepts_and_completes_gig(self):
        worker=self.register_worker('worker@test.invalid')
        self.client.post('/api/auth/logout')
        reviewed=self.review_worker(worker,identity_state='approved',approval_state='approved',training_complete=True)
        self.assertEqual(reviewed.status_code,200,reviewed.text)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        gig=self.create_gig()
        self.client.post('/api/auth/logout')
        self.login(self.client,'worker@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,200)
        offered=self.client.get('/api/bookings').json()
        self.assertEqual(len(offered),1)
        self.assertEqual(offered[0]['person'],'Care recipient')
        self.assertNotIn('client_details',offered[0])
        accepted=self.client.post(f"/api/bookings/{gig['id']}/accept",json={})
        self.assertEqual(accepted.status_code,200,accepted.text)
        assigned=self.client.get('/api/bookings').json()[0]
        self.assertEqual(assigned['client_details']['address'],'12 Sample Road, Jayanagar, Bengaluru')
        self.assertEqual(self.client.post(f"/api/bookings/{gig['id']}/progress",json={'status':'reached'}).status_code,409)
        for status in ('on_way','reached','helping'):
            self.clock+=timedelta(seconds=1)
            response=self.client.post(f"/api/bookings/{gig['id']}/progress",json={'status':status})
            self.assertEqual(response.status_code,201,response.text)
        self.clock+=timedelta(seconds=1)
        wrong=self.client.post(f"/api/bookings/{gig['id']}/progress",json={'status':'done','completion_code':'000000'})
        self.assertEqual(wrong.status_code,403)
        done=self.client.post(f"/api/bookings/{gig['id']}/progress",json={'status':'done','completion_code':gig['completion_code']})
        self.assertEqual(done.status_code,201,done.text)
        self.assertEqual(self.client.get('/api/contributor/earnings').json()['pending_inr'],240)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        self.assertTrue(any(n['event_type']=='gig_done' for n in self.client.get('/api/admin/notifications').json()))
        self.assertEqual(self.client.get('/api/admin/gigs').json()[0]['progress'],'done')
        analytics=self.client.get('/api/admin/analytics').json()
        self.assertEqual(analytics['completed'],1)
        self.assertEqual(analytics['accepted_gigs'],1)
        self.assertEqual(analytics['pending_gigs'],0)
        self.assertEqual(analytics['pending_payout_inr'],240)
        earnings=self.client.get('/api/admin/earnings').json()
        self.assertEqual(earnings[0]['status'],'pending')
        paid=self.client.post(f"/api/admin/earnings/{earnings[0]['id']}/mark-paid",json={'payment_reference':'settlement-demo-1'})
        self.assertEqual(paid.status_code,200,paid.text)
        pass_gig=self.create_gig(title='Optional visit')
        self.client.post('/api/auth/logout')
        self.login(self.client,'worker@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.post(f"/api/bookings/{pass_gig['id']}/ignore",json={}).status_code,201)
        self.assertNotIn(pass_gig['id'],[b['id'] for b in self.client.get('/api/bookings').json()])
        self.assertTrue(self.client.get('/api/contributor').json()['availability'])
        self.assertEqual(self.client.get('/api/contributor/earnings').json()['paid_inr'],240)

    def test_two_workers_cannot_claim_same_gig(self):
        first=self.register_worker('first@test.invalid')
        self.client.post('/api/auth/logout')
        self.review_worker(first,identity_state='approved',approval_state='approved',training_complete=True)
        self.client.post('/api/auth/logout')
        second_client=TestClient(service.app)
        try:
            second=self.register_worker('second@test.invalid',second_client)
            self.client.post('/api/auth/logout')
            self.review_worker(second,identity_state='approved',approval_state='approved',training_complete=True)
            self.client.post('/api/auth/logout')
            self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
            gig=self.create_gig(title='Shared offer')
            worker_clients=[]
            for c,email in ((self.client,'first@test.invalid'),(second_client,'second@test.invalid')):
                c.post('/api/auth/logout')
                self.login(c,email,'Secure-test-password-491!')
                self.assertEqual(c.patch('/api/contributor/availability',json={'available':True}).status_code,200)
                worker_clients.append(c)
            def claim(c):return c.post(f"/api/bookings/{gig['id']}/accept",json={}).status_code
            with ThreadPoolExecutor(max_workers=2) as pool: codes=list(pool.map(claim,worker_clients))
            self.assertEqual(sorted(codes),[200,409])
            loser=worker_clients[codes.index(409)]
            self.assertNotIn(gig['id'],[row['id'] for row in loser.get('/api/bookings').json()])
            self.assertEqual(loser.post(f"/api/bookings/{gig['id']}/progress",json={'status':'on_way'}).status_code,403)
        finally:
            second_client.close()

    def test_suspended_worker_can_only_read_eligibility_status(self):
        worker=self.register_worker('suspended@test.invalid')
        self.client.post('/api/auth/logout')
        self.review_worker(worker,active=False)
        self.client.post('/api/auth/logout')
        self.login(self.client,'suspended@test.invalid','Secure-test-password-491!')
        self.assertFalse(self.client.get('/api/auth/me').json()['active'])
        status=self.client.get('/api/contributor').json()
        self.assertIn('Your account is suspended.',status['ineligibility_reasons'])
        self.assertEqual(self.client.get('/api/bookings').status_code,401)
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':False}).status_code,401)

    def test_admin_can_offer_to_one_eligible_worker(self):
        worker=self.register_worker('target@test.invalid')
        self.client.post('/api/auth/logout')
        self.review_worker(worker,identity_state='approved',approval_state='approved',training_complete=True)
        self.client.post('/api/auth/logout')
        self.login(self.client,'target@test.invalid','Secure-test-password-491!')
        self.assertEqual(self.client.patch('/api/contributor/availability',json={'available':True}).status_code,200)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        gig=self.create_gig(title='Selected worker offer',assigned_worker_id=worker)
        self.assertEqual(gig['status'],'offered')
        self.client.post('/api/auth/logout')
        self.login(self.client,'target@test.invalid','Secure-test-password-491!')
        rows=self.client.get('/api/bookings').json()
        self.assertEqual([row['id'] for row in rows],[gig['id']])
        accepted=self.client.post(f"/api/bookings/{gig['id']}/accept",json={})
        self.assertEqual(accepted.status_code,200,accepted.text)

    def test_admin_can_cancel_an_unassigned_gig(self):
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        gig=self.create_gig(title='Cancelled task')
        result=self.client.post(f"/api/bookings/{gig['id']}/cancel",json={})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['status'],'cancelled')
        events=self.client.get('/api/admin/notifications').json()
        self.assertTrue(any(e['event_type']=='gig_cancelled' for e in events))

    def test_admin_documented_completion_exception(self):
        worker=self.register_worker('exception@test.invalid')
        self.client.post('/api/auth/logout')
        self.review_worker(worker,identity_state='approved',approval_state='approved',training_complete=True)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        gig=self.create_gig(title='Completion exception task')
        self.client.post('/api/auth/logout')
        self.login(self.client,'exception@test.invalid','Secure-test-password-491!')
        self.client.patch('/api/contributor/availability',json={'available':True})
        self.client.post(f"/api/bookings/{gig['id']}/accept",json={})
        for status in ('on_way','reached','helping'):
            self.clock+=timedelta(seconds=1)
            self.assertEqual(self.client.post(f"/api/bookings/{gig['id']}/progress",json={'status':status}).status_code,201)
        self.client.post('/api/auth/logout')
        self.login(self.client,'operator@test.invalid','Operator-test-password-473!')
        self.assertEqual(self.client.post(f"/api/admin/gigs/{gig['id']}/complete-exception",json={'reason':'No'}).status_code,422)
        resolved=self.client.post(f"/api/admin/gigs/{gig['id']}/complete-exception",json={'reason':'Client confirmed the visit with the coordinator; completion code could not be delivered.'})
        self.assertEqual(resolved.status_code,200,resolved.text)
        self.assertTrue(resolved.json()['completion_exception'])
        self.assertTrue(any(e['action']=='gig_completed_by_exception' for e in self.client.get('/api/admin/audit').json()))

if __name__=='__main__':
    unittest.main()
