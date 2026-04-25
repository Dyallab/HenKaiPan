UPDATE notification_settings
SET alert_high = TRUE,
    updated_at = NOW()
WHERE singleton = TRUE
  AND alert_high = FALSE;
