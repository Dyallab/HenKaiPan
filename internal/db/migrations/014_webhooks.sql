CREATE TABLE IF NOT EXISTS webhooks (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    label         TEXT        NOT NULL,
    url           TEXT        NOT NULL,
    events        JSONB       NOT NULL DEFAULT '[]',
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_delivery TIMESTAMPTZ,
    delivery_count INT        NOT NULL DEFAULT 0,
    error_count   INT         NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled);

CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id    UUID        NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type    TEXT        NOT NULL,
    payload       JSONB       NOT NULL,
    status_code   INT,
    response_body TEXT,
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_webhook_id ON webhook_delivery_logs(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_created_at ON webhook_delivery_logs(created_at);
