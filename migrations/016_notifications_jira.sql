CREATE TABLE IF NOT EXISTS notification_settings (
    singleton          BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
    alert_critical     BOOLEAN     NOT NULL DEFAULT TRUE,
    alert_high         BOOLEAN     NOT NULL DEFAULT FALSE,
    alert_scan_complete BOOLEAN    NOT NULL DEFAULT TRUE,
    alert_scan_failed  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO notification_settings (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS jira_integrations (
    singleton   BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
    base_url    TEXT        NOT NULL DEFAULT '',
    user_email  TEXT        NOT NULL DEFAULT '',
    project_key TEXT        NOT NULL DEFAULT '',
    issue_type  TEXT        NOT NULL DEFAULT 'Task',
    labels      JSONB       NOT NULL DEFAULT '[]',
    token       TEXT        NOT NULL DEFAULT '',
    enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO jira_integrations (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS jira_issue_links (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID        NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    issue_key  TEXT,
    issue_url  TEXT,
    status     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jira_issue_links_issue_key ON jira_issue_links(issue_key);
