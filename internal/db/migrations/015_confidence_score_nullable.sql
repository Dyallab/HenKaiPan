ALTER TABLE findings
    ALTER COLUMN confidence_score DROP DEFAULT,
    ALTER COLUMN confidence_score DROP NOT NULL;

UPDATE findings
SET confidence_score = NULL
WHERE confidence_score = 0.5
  AND corroboration_count = 0;
