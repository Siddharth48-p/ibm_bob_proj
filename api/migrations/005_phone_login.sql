ALTER TABLE users ADD COLUMN account_phone_hash TEXT;
CREATE UNIQUE INDEX users_phone_hash_uq ON users(account_phone_hash) WHERE account_phone_hash IS NOT NULL;
