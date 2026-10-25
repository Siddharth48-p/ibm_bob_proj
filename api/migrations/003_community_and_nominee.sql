ALTER TABLE users ADD COLUMN account_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN account_phone_ciphertext TEXT;
ALTER TABLE users ADD COLUMN account_relationship TEXT NOT NULL DEFAULT '';
CREATE TABLE community_requests (
 id TEXT PRIMARY KEY,
 requested_by TEXT NOT NULL REFERENCES users(id),
 name TEXT NOT NULL,
 topic TEXT NOT NULL,
 area TEXT NOT NULL,
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 reviewed_by TEXT REFERENCES users(id),
 review_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX community_requests_status_idx ON community_requests(status,created_at);
CREATE TABLE communities (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 topic TEXT NOT NULL,
 area TEXT NOT NULL,
 description TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES users(id),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused')),
 created_at TEXT NOT NULL
);
CREATE TABLE community_members (
 community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 joined_at TEXT NOT NULL,
 PRIMARY KEY(community_id,user_id)
);
CREATE TABLE community_posts (
 id TEXT PRIMARY KEY,
 community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id),
 message TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX community_posts_time_idx ON community_posts(community_id,created_at);
ALTER TABLE bookings ADD COLUMN checkin_otp_ciphertext TEXT;
ALTER TABLE bookings ADD COLUMN checkout_otp_ciphertext TEXT;
