ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'guardian' CHECK(account_type IN ('guardian','elder'));
CREATE TABLE identity_verification_requests (
 id TEXT PRIMARY KEY,
 guardian_user_id TEXT NOT NULL REFERENCES users(id),
 elder_profile_id TEXT NOT NULL UNIQUE REFERENCES profiles(id),
 guardian_identity_reference_ciphertext TEXT NOT NULL,
 elder_identity_reference_ciphertext TEXT NOT NULL,
 relationship_proof_reference_ciphertext TEXT,
 relationship_proof_type TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','verified','rejected')),
 reviewed_by TEXT REFERENCES users(id),
 review_note TEXT NOT NULL DEFAULT '',
 submitted_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX identity_verification_status_idx ON identity_verification_requests(status,submitted_at);
