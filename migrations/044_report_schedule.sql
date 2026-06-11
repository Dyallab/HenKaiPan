ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS report_schedule TEXT NOT NULL DEFAULT 'disabled';
ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS report_time TEXT NOT NULL DEFAULT '09:00';
ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS report_channel TEXT NOT NULL DEFAULT 'email';
