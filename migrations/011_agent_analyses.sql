CREATE TABLE IF NOT EXISTS agent_analyses (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id    UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    agent_type    TEXT NOT NULL DEFAULT 'validator',
    confidence    FLOAT NOT NULL DEFAULT 0,
    fp_likelihood TEXT NOT NULL DEFAULT 'unknown',
    reasoning     TEXT,
    raw_output    JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_analyses_finding_type
    ON agent_analyses(finding_id, agent_type);

CREATE TABLE IF NOT EXISTS finding_correlations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id_a     UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    finding_id_b     UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    correlation_type TEXT NOT NULL DEFAULT 'same_location',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_finding_correlations UNIQUE (finding_id_a, finding_id_b)
);
