ALTER TABLE contributors ADD COLUMN identity_mode TEXT NOT NULL DEFAULT 'development_sandbox';
ALTER TABLE contributors ADD COLUMN approval_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE contributors ADD COLUMN training_changed_by TEXT REFERENCES users(id);
ALTER TABLE contributors ADD COLUMN training_updated_at TEXT;
ALTER TABLE contributors ADD COLUMN availability_changed_at TEXT;
ALTER TABLE contributors ADD COLUMN suspended_at TEXT;
ALTER TABLE contributors ADD COLUMN home_address_ciphertext TEXT NOT NULL DEFAULT '';
ALTER TABLE bookings ADD COLUMN gig_title TEXT NOT NULL DEFAULT '';
ALTER TABLE bookings ADD COLUMN gig_description TEXT NOT NULL DEFAULT '';
ALTER TABLE bookings ADD COLUMN required_skills TEXT NOT NULL DEFAULT '[]';
ALTER TABLE bookings ADD COLUMN priority TEXT NOT NULL DEFAULT 'standard';
ALTER TABLE bookings ADD COLUMN helpers_needed INTEGER NOT NULL DEFAULT 1;
CREATE TABLE organization_notifications (
 id TEXT PRIMARY KEY,
 event_type TEXT NOT NULL,
 title TEXT NOT NULL,
 body TEXT NOT NULL,
 entity_type TEXT NOT NULL DEFAULT '',
 entity_id TEXT NOT NULL DEFAULT '',
 read_at TEXT,
 created_at TEXT NOT NULL
);
CREATE INDEX organization_notifications_recent_idx ON organization_notifications(read_at,created_at DESC);
CREATE TABLE worker_earnings (
 id TEXT PRIMARY KEY,
 booking_id TEXT NOT NULL UNIQUE REFERENCES bookings(id),
 worker_user_id TEXT NOT NULL REFERENCES users(id),
 amount_inr INTEGER NOT NULL CHECK(amount_inr>=0),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid')),
 recorded_at TEXT NOT NULL,
 paid_at TEXT,
 paid_by TEXT REFERENCES users(id),
 payment_reference TEXT NOT NULL DEFAULT ''
);
CREATE INDEX worker_earnings_worker_idx ON worker_earnings(worker_user_id,recorded_at DESC);
