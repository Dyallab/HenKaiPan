-- Migration 030: Finding Comments
-- Adds threaded comments to findings for team collaboration

CREATE TABLE IF NOT EXISTS finding_comments (
    id BIGSERIAL PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (char_length(content) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_finding_comments_finding_id ON finding_comments(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_comments_created ON finding_comments(created_at DESC);

CREATE OR REPLACE FUNCTION update_finding_comment_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_comment_updated_at
    BEFORE UPDATE ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_finding_comment_updated_at();

ALTER TABLE findings ADD COLUMN IF NOT EXISTS comment_count INTEGER NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION update_finding_comment_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE findings SET comment_count = comment_count + 1 WHERE id = NEW.finding_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE findings SET comment_count = comment_count - 1 WHERE id = OLD.finding_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_comment_count_insert
    AFTER INSERT ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_finding_comment_count();

CREATE TRIGGER trg_finding_comment_count_delete
    AFTER DELETE ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_finding_comment_count();
