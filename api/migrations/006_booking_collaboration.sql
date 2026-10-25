ALTER TABLE bookings ADD COLUMN helper_accepted_at TEXT;
CREATE TABLE care_profile_access (
 profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 granted_by TEXT NOT NULL REFERENCES users(id),
 linked_at TEXT NOT NULL,
 PRIMARY KEY(profile_id,user_id)
);
CREATE INDEX care_profile_access_user_idx ON care_profile_access(user_id,profile_id);
