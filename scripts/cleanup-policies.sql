-- Cleanup script for local development
-- Removes "High Risk Findings Escalation" policy and disables all non-custom policies

DELETE FROM policies 
WHERE name = 'High Risk Findings Escalation' 
  AND pack_type = 'iso27001-basics';

UPDATE policies 
SET enabled = FALSE 
WHERE pack_type != 'custom';

SELECT name, pack_type, enabled 
FROM policies 
ORDER BY pack_type, name;
