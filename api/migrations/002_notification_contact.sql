ALTER TABLE profiles ADD COLUMN notification_name TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN notification_phone_ciphertext TEXT;
ALTER TABLE profiles ADD COLUMN notification_relationship TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN notification_contact_consent INTEGER NOT NULL DEFAULT 0;
