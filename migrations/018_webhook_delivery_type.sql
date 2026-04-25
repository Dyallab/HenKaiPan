ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS delivery_type TEXT NOT NULL DEFAULT 'generic';

UPDATE webhooks
SET delivery_type = 'generic'
WHERE delivery_type IS NULL OR delivery_type = '';
