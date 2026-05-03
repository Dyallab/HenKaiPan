CREATE TABLE IF NOT EXISTS apps (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    team_id     UUID REFERENCES teams(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    app_id      UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    repo_id     UUID REFERENCES repos(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, name),
    UNIQUE(repo_id)
);

CREATE INDEX IF NOT EXISTS idx_apps_team_id      ON apps(team_id);
CREATE INDEX IF NOT EXISTS idx_projects_app_id   ON projects(app_id);
CREATE INDEX IF NOT EXISTS idx_projects_repo_id  ON projects(repo_id);
