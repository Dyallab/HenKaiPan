CREATE TABLE IF NOT EXISTS usage_counters (
    key        TEXT PRIMARY KEY,
    value      INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_counters_key ON usage_counters(key);
