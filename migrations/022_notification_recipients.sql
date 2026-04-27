ALTER TABLE notification_settings
    ADD COLUMN IF NOT EXISTS email_recipients JSONB NOT NULL DEFAULT '[]';

UPDATE notification_settings
SET email_recipients = '[]'
WHERE email_recipients IS NULL;
