"""Isolated API integration checks; SQLite is used only as a test database."""
from datetime import date, datetime, time, timedelta, timezone
import os
import asyncio
import tempfile
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient

from api import db, settings
import api.main as service
from api.security import password_hash
from api.worker import schedule_due_reminders, deliver_notifications


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self):
        database_dir = Path(__file__).resolve().parents[1] / "data" / "test-databases"
        database_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = database_dir / f"test-{os.getpid()}-{id(self)}.db"
        settings.DATABASE_URL = "sqlite:///" + str(self.database_path)
        settings.APP_SECRET = "test-only-secret-with-over-32-characters-0001"
        settings.APP_ENV = "test"
        settings.INTEGRATION_KEY = "test-integration-key"
        self.clock = datetime.combine(date.today(), time(9,20), ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
        service.now = lambda: self.clock
        # Field crypto has a dedicated Fernet dependency in the production image.
        # These route tests cover access/business flows and keep test fixtures synthetic.
        service.encrypt = lambda value: value
        service.decrypt = lambda value: value
        db.migrate()
        self.client = TestClient(service.app)
        self.operator_id = "operator-test-id"
        with db.transaction() as conn:
            conn.execute("INSERT INTO users(id,email,password_hash,role,created_at) VALUES(?,?,?,'operator',?)",
                         (self.operator_id, "operator@test.invalid", password_hash("Operator-test-password-473!"), datetime.now(timezone.utc).isoformat()))

    def tearDown(self):
        self.client.close()
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.database_path)+suffix)
            if path.exists():
                path.unlink()

    def register_login(self, email, role):
        response = self.client.post("/api/auth/register", json={"email": email, "password": "Secure-test-password-491!", "role": role})
        self.assertEqual(response.status_code, 201, response.text)
        response = self.client.post("/api/auth/login", json={"email": email, "password": "Secure-test-password-491!"})
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers.update({"X-CSRF-Token": response.json()["csrf_token"]})
        return response.json()["user"]["id"]

    def sign_in_operator(self):
        response = self.client.post("/api/auth/login", json={"email": "operator@test.invalid", "password": "Operator-test-password-473!"})
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers.update({"X-CSRF-Token": response.json()["csrf_token"]})

    def test_family_contributor_operator_booking_and_otp_workflow(self):
        customer_id = self.register_login("family@test.invalid", "family")
        profile = self.client.post("/api/profiles", json={"display_name":"Test Elder","age":74,"language":"Kannada","city":"Bengaluru","service_area":"Jayanagar","consent_confirmed":True,"family_access":True,"monitoring_consent":True,"voice_ai_consent":True}).json()

        future = service.india_now().date()
        booking = self.client.post("/api/bookings", json={"profile_id":profile["id"],"category":"companionship","service_date":future.isoformat(),"start_time":"10:00","duration_hours":1,"language":"Kannada","instructions":"Meet at agreed public location"})
        self.assertEqual(booking.status_code, 201, booking.text)
        record = booking.json()
        self.assertEqual(record["status"], "searching")
        self.assertEqual(len(record["checkin_otp"]), 6)

        contributor_id = self.register_login("contributor@test.invalid", "contributor")
        submitted = self.client.post("/api/contributor/onboarding", json={"display_name":"Test Helper","city":"Bengaluru","service_area":"Jayanagar","languages":["Kannada"],"tasks":["companionship"]})
        self.assertEqual(submitted.status_code, 201)
        training = ["Call emergency services and notify the coordinator", "no", "Call emergency services when warranted and notify the coordinator"]
        self.assertTrue(self.client.post("/api/contributor/training/complete", json=training).json()["passed"])

        self.sign_in_operator()
        reviewed = self.client.patch(f"/api/admin/contributors/{contributor_id}", json={"identity_state":"approved"})
        self.assertEqual(reviewed.status_code, 200, reviewed.text)
        self.client.post("/api/auth/logout")
        self.client.post("/api/auth/login", json={"email":"contributor@test.invalid","password":"Secure-test-password-491!"})
        self.client.headers.update({"X-CSRF-Token":self.client.get("/api/auth/csrf").json()["csrf_token"]})
        self.client.patch("/api/contributor/availability", json={"available":True})
        accepted = self.client.post(f"/api/bookings/{record['id']}/accept", json={})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(self.client.post(f"/api/bookings/{record['id']}/check-in", json={"otp":record["checkin_otp"]}).status_code, 409)
        self.clock = datetime.combine(future, time(9,40), ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
        self.assertEqual(self.client.post(f"/api/bookings/{record['id']}/check-in", json={"otp":"000000"}).status_code, 422)
        self.assertEqual(self.client.post(f"/api/bookings/{record['id']}/check-in", json={"otp":record["checkin_otp"]}).json()["status"], "in_progress")
        self.clock = datetime.combine(future, time(10,5), ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
        self.assertEqual(self.client.post(f"/api/bookings/{record['id']}/check-out", json={"otp":record["checkout_otp"]}).json()["status"], "completed")

        self.client.post("/api/auth/logout")
        self.client.post("/api/auth/login", json={"email":"family@test.invalid","password":"Secure-test-password-491!"})
        self.client.headers.update({"X-CSRF-Token":self.client.get("/api/auth/csrf").json()["csrf_token"]})
        completed = self.client.get("/api/bookings").json()
        self.assertEqual(completed[0]["status"], "completed")
        self.assertEqual(completed[0]["service_area"], "Jayanagar")
        self.assertEqual(self.client.post("/api/bookings", json={"profile_id":profile["id"],"category":"intimate hygiene","service_date":future.isoformat(),"start_time":"10:00","duration_hours":1,"language":"Kannada"}).status_code, 422)

        with db.transaction() as conn:
            message_id = "message-review-test"
            conn.execute("INSERT INTO messages(id,provider,provider_message_id,direction,kind,received_at,status,intent,transcript) VALUES(?,'whatsapp',?,'inbound','voice',?,'human_review','unclear','Please arrange a companion visit')", (message_id, message_id, service.stamp()))
        self.client.post("/api/auth/logout")
        self.sign_in_operator()
        queue = self.client.get("/api/messages")
        self.assertTrue(any(item["id"] == message_id for item in queue.json()))
        reviewed = self.client.post(f"/api/admin/messages/{message_id}/review", json={"note":"Confirmed with family"})
        self.assertEqual(reviewed.status_code, 200, reviewed.text)
        self.assertEqual(reviewed.json()["status"], "reviewed")
        self.client.post("/api/auth/logout")
        self.client.post("/api/auth/login", json={"email":"family@test.invalid","password":"Secure-test-password-491!"})
        self.client.headers.update({"X-CSRF-Token":self.client.get("/api/auth/csrf").json()["csrf_token"]})

        replacement_booking=self.client.post("/api/bookings",json={"profile_id":profile["id"],"category":"companionship","service_date":future.isoformat(),"start_time":"11:00","duration_hours":1,"language":"Kannada"}).json()
        self.client.post("/api/auth/logout")
        self.client.post("/api/auth/login",json={"email":"contributor@test.invalid","password":"Secure-test-password-491!"})
        self.client.headers.update({"X-CSRF-Token":self.client.get("/api/auth/csrf").json()["csrf_token"]})
        self.assertEqual(self.client.post(f"/api/bookings/{replacement_booking['id']}/accept",json={}).status_code,200)
        recovery=self.client.post(f"/api/bookings/{replacement_booking['id']}/cancel",json={})
        self.assertEqual(recovery.status_code,200)
        self.assertEqual(recovery.json()["status"],"unfilled")
        self.assertIn("BLOCKED",recovery.json()["partner_fallback"])

    def test_monitoring_consent_alert_lifecycle_and_payment_block(self):
        self.register_login("family2@test.invalid", "family")
        profile = self.client.post("/api/profiles", json={"display_name":"Consent Test","city":"Bengaluru","service_area":"Indiranagar","language":"English","consent_confirmed":True,"family_access":True,"monitoring_consent":True,"voice_ai_consent":False}).json()
        no_consent = self.client.post("/api/profiles", json={"display_name":"No Consent","city":"Bengaluru","service_area":"Indiranagar","consent_confirmed":False})
        self.assertEqual(no_consent.status_code, 422)

        reading = self.client.post("/api/integrations/wearables/readings", headers={"X-Integration-Key":"test-integration-key"}, json={"profile_id":profile["id"],"provider":"fitbit","metric":"heart_rate","value":180,"unit":"bpm","observed_at":service.now().isoformat(),"event_key":"test-reading-1"})
        self.assertEqual(reading.status_code, 201, reading.text)
        self.assertEqual(reading.json()["alert_category"], "yellow")
        duplicate = self.client.post("/api/integrations/wearables/readings", headers={"X-Integration-Key":"test-integration-key"}, json={"profile_id":profile["id"],"provider":"fitbit","metric":"heart_rate","value":180,"unit":"bpm","observed_at":service.now().isoformat(),"event_key":"test-reading-1"})
        self.assertTrue(duplicate.json()["duplicate"])

        self.sign_in_operator()
        alert = self.client.get("/api/alerts").json()[0]
        self.assertEqual(self.client.post(f"/api/alerts/{alert['id']}/resolve", json={"response_note":"reviewed"}).status_code, 409)
        self.assertEqual(self.client.post(f"/api/alerts/{alert['id']}/acknowledge", json={}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/alerts/{alert['id']}/resolve", json={"response_note":"Called family and confirmed safe"}).json()["status"], "closed")
        self.assertEqual(self.client.post("/api/bookings/nonexistent/payments/order", json={}).status_code, 403)

    def test_session_permissions_and_duplicate_registration(self):
        self.register_login("family3@test.invalid", "family")
        self.assertEqual(self.client.get("/api/admin/overview").status_code, 403)
        self.assertEqual(self.client.post("/api/auth/register", json={"email":"family3@test.invalid","password":"Secure-test-password-491!","role":"family"}).status_code, 409)
        self.client.post("/api/auth/logout")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

    def test_due_reminder_is_queued_and_blocked_without_whatsapp_credentials(self):
        self.register_login("reminder@test.invalid", "family")
        profile=self.client.post("/api/profiles",json={"display_name":"Reminder Test","city":"Bengaluru","service_area":"Indiranagar","language":"English","consent_confirmed":True,"family_access":True}).json()
        due=(service.now()+timedelta(hours=1)).isoformat()
        reminder=self.client.post("/api/reminders",json={"profile_id":profile["id"],"title":"Daily check-in","due_at":due})
        self.assertEqual(reminder.status_code,201,reminder.text)
        with db.transaction() as conn:
            conn.execute("UPDATE reminders SET due_at=?,next_attempt_at=? WHERE id=?",((service.now()-timedelta(seconds=1)).isoformat(),(service.now()-timedelta(seconds=1)).isoformat(),reminder.json()["id"]))
        settings.WHATSAPP_TOKEN=settings.WHATSAPP_PHONE_NUMBER_ID=settings.WHATSAPP_VERIFY_TOKEN=settings.WHATSAPP_APP_SECRET=""
        settings.WHATSAPP_TEMPLATE_BOOKING=settings.WHATSAPP_TEMPLATE_REMINDER=""
        asyncio.run(schedule_due_reminders())
        asyncio.run(deliver_notifications())
        with db.transaction() as conn:
            state=conn.one("SELECT status FROM reminders WHERE id=?",(reminder.json()["id"],))["status"]
            notification=conn.one("SELECT status FROM notifications WHERE profile_id=? ORDER BY created_at DESC LIMIT 1",(profile["id"],))["status"]
        self.assertEqual(state,"blocked")
        self.assertEqual(notification,"blocked")
        self.client.post("/api/auth/logout")
        self.sign_in_operator()
        with db.transaction() as conn:
            notification_id=conn.one("SELECT id FROM notifications WHERE profile_id=? ORDER BY created_at DESC LIMIT 1",(profile["id"],))["id"]
        queue=self.client.get("/api/admin/queue").json()
        self.assertTrue(any(item["id"]==notification_id for item in queue["retryable_notifications"]))
        retried=self.client.post(f"/api/admin/notifications/{notification_id}/retry",json={})
        self.assertEqual(retried.status_code,200,retried.text)
        with db.transaction() as conn:
            self.assertEqual(conn.one("SELECT status FROM reminders WHERE id=?",(reminder.json()["id"],))["status"],"queued")


if __name__ == "__main__":
    unittest.main(verbosity=2)
