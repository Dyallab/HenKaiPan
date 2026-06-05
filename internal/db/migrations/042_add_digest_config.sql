ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS digest_frequency TEXT NOT NULL DEFAULT 'weekly';
ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS digest_time TEXT NOT NULL DEFAULT '09:00';
