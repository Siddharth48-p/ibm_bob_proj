ALTER TABLE contributors ADD COLUMN date_of_birth TEXT;
ALTER TABLE contributors ADD COLUMN age INTEGER;
ALTER TABLE contributors ADD COLUMN profession TEXT NOT NULL DEFAULT '';
ALTER TABLE contributors ADD COLUMN identity_document_type TEXT NOT NULL DEFAULT '';
ALTER TABLE contributors ADD COLUMN identity_reference_ciphertext TEXT;
ALTER TABLE profiles ADD COLUMN address_ciphertext TEXT;
CREATE TABLE booking_ignored (helper_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, booking_id TEXT NOT NULL REFERENCES bookings(id) ON DELETE CASCADE, created_at TEXT NOT NULL, PRIMARY KEY(helper_user_id,booking_id));
CREATE TABLE booking_updates (id TEXT PRIMARY KEY, booking_id TEXT NOT NULL REFERENCES bookings(id) ON DELETE CASCADE, helper_user_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL CHECK(status IN ('on_way','reached','helping','done')), created_at TEXT NOT NULL);
CREATE INDEX booking_updates_recent_idx ON booking_updates(created_at DESC);
