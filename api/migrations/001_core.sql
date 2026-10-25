CREATE TABLE users (
 id TEXT PRIMARY KEY,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('family','contributor','operator')),
 is_active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY,
 csrf_hash TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE auth_rate_limits (
 key_hash TEXT PRIMARY KEY,
 window_started_at TEXT NOT NULL,
 attempts INTEGER NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE TABLE profiles (
 id TEXT PRIMARY KEY,
 owner_user_id TEXT NOT NULL REFERENCES users(id),
 display_name TEXT NOT NULL,
 age INTEGER,
 phone TEXT,
 whatsapp_ciphertext TEXT,
 whatsapp_id_hash TEXT UNIQUE,
 language TEXT NOT NULL DEFAULT 'English',
 city TEXT NOT NULL,
 service_area TEXT NOT NULL,
 consent_confirmed INTEGER NOT NULL DEFAULT 0,
 family_access INTEGER NOT NULL DEFAULT 0,
 monitoring_consent INTEGER NOT NULL DEFAULT 0,
 voice_ai_consent INTEGER NOT NULL DEFAULT 0,
 retention_days INTEGER NOT NULL DEFAULT 30,
 created_at TEXT NOT NULL
);
CREATE INDEX profiles_owner_idx ON profiles(owner_user_id);
CREATE TABLE contributors (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 service_area TEXT NOT NULL,
 city TEXT NOT NULL,
 languages TEXT NOT NULL,
 tasks TEXT NOT NULL,
 identity_state TEXT NOT NULL DEFAULT 'pending' CHECK(identity_state IN ('pending','approved','rejected')),
 training_complete INTEGER NOT NULL DEFAULT 0,
 qualification_passed INTEGER NOT NULL DEFAULT 0,
 availability INTEGER NOT NULL DEFAULT 0,
 payout_inr INTEGER NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX contributors_eligible_idx ON contributors(identity_state,training_complete,qualification_passed,availability);
CREATE TABLE bookings (
 id TEXT PRIMARY KEY,
 customer_user_id TEXT NOT NULL REFERENCES users(id),
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 contributor_user_id TEXT REFERENCES users(id),
 category TEXT NOT NULL,
 service_date TEXT NOT NULL,
 start_time TEXT NOT NULL,
 duration_hours INTEGER NOT NULL CHECK(duration_hours BETWEEN 1 AND 8),
 city TEXT NOT NULL,
 service_area TEXT NOT NULL,
 language TEXT NOT NULL,
 instructions TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL CHECK(status IN ('searching','offered','confirmed','in_progress','completed','cancelled','unfilled')),
 price_inr INTEGER NOT NULL,
 payout_inr INTEGER NOT NULL,
 checkin_otp_hash TEXT NOT NULL,
 checkout_otp_hash TEXT NOT NULL,
 otp_expires_at TEXT NOT NULL,
 checkin_at TEXT,
 checkout_at TEXT,
 payment_state TEXT NOT NULL DEFAULT 'unpaid',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX bookings_customer_idx ON bookings(customer_user_id,service_date);
CREATE INDEX bookings_contributor_idx ON bookings(contributor_user_id,status,service_date);
CREATE INDEX bookings_status_idx ON bookings(status,service_date,start_time);
CREATE TABLE alerts (
 id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 category TEXT NOT NULL CHECK(category IN ('routine','yellow','red')),
 title TEXT NOT NULL,
 source TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','assigned','closed')),
 assigned_user_id TEXT REFERENCES users(id),
 response_note TEXT NOT NULL DEFAULT '',
 event_key TEXT UNIQUE,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX alerts_queue_idx ON alerts(status,category,created_at);
CREATE TABLE sensor_readings (
 id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 provider TEXT NOT NULL,
 metric TEXT NOT NULL,
 value REAL NOT NULL,
 unit TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 quality TEXT NOT NULL DEFAULT 'unreviewed',
 event_key TEXT UNIQUE
);
CREATE INDEX sensor_profile_time_idx ON sensor_readings(profile_id,observed_at);
CREATE TABLE incidents (
 id TEXT PRIMARY KEY,
 booking_id TEXT REFERENCES bookings(id),
 profile_id TEXT REFERENCES profiles(id),
 filed_by TEXT NOT NULL REFERENCES users(id),
 category TEXT NOT NULL,
 description TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',
 resolution TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX incidents_queue_idx ON incidents(status,created_at);
CREATE TABLE feedback (
 id TEXT PRIMARY KEY,
 booking_id TEXT NOT NULL UNIQUE REFERENCES bookings(id),
 customer_user_id TEXT NOT NULL REFERENCES users(id),
 rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
 comment TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE cancellation_events (
 id TEXT PRIMARY KEY,
 booking_id TEXT NOT NULL REFERENCES bookings(id),
 initiated_by TEXT NOT NULL REFERENCES users(id),
 cancelled_contributor_id TEXT REFERENCES users(id),
 replacement_contributor_id TEXT REFERENCES users(id),
 result TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX cancellations_created_idx ON cancellation_events(created_at);
CREATE TABLE payments (
 id TEXT PRIMARY KEY,
 booking_id TEXT NOT NULL REFERENCES bookings(id),
 provider TEXT NOT NULL,
 provider_order_id TEXT UNIQUE,
 provider_payment_id TEXT UNIQUE,
 amount_inr INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'created',
 refund_state TEXT NOT NULL DEFAULT 'none',
 provider_payload TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE payment_events (
 event_id TEXT PRIMARY KEY,
 payment_id TEXT REFERENCES payments(id),
 payload_hash TEXT NOT NULL,
 received_at TEXT NOT NULL
);
CREATE TABLE reminders (
 id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 created_by TEXT NOT NULL REFERENCES users(id),
 title TEXT NOT NULL,
 due_at TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'scheduled',
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TEXT NOT NULL,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE INDEX reminders_due_idx ON reminders(status,next_attempt_at);
CREATE TABLE notifications (
 id TEXT PRIMARY KEY,
 profile_id TEXT REFERENCES profiles(id),
 destination TEXT,
 channel TEXT NOT NULL,
 message_type TEXT NOT NULL,
 payload TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TEXT NOT NULL,
 provider_message_id TEXT,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX notifications_queue_idx ON notifications(status,next_attempt_at);
CREATE TABLE messages (
 id TEXT PRIMARY KEY,
 provider TEXT NOT NULL,
 provider_message_id TEXT NOT NULL UNIQUE,
 profile_id TEXT REFERENCES profiles(id),
 direction TEXT NOT NULL,
 kind TEXT NOT NULL,
 received_at TEXT NOT NULL,
 status TEXT NOT NULL,
 intent TEXT NOT NULL DEFAULT '',
 transcript TEXT NOT NULL DEFAULT ''
);
CREATE TABLE audit_log (
 id TEXT PRIMARY KEY,
 actor_user_id TEXT REFERENCES users(id),
 action TEXT NOT NULL,
 entity_type TEXT NOT NULL,
 entity_id TEXT NOT NULL,
 metadata TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL
);
CREATE INDEX audit_entity_idx ON audit_log(entity_type,entity_id,created_at);
CREATE TABLE oauth_states (
 state_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 expires_at TEXT NOT NULL
);
CREATE TABLE voice_jobs (
 id TEXT PRIMARY KEY,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(id),
 media_id TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TEXT NOT NULL,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE provider_tokens (
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 provider TEXT NOT NULL,
 access_token TEXT NOT NULL,
 refresh_token TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 PRIMARY KEY(profile_id,provider)
);
CREATE TABLE worker_heartbeat (
 name TEXT PRIMARY KEY,
 last_seen_at TEXT NOT NULL
);
