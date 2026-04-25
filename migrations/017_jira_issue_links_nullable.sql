ALTER TABLE jira_issue_links
    ALTER COLUMN issue_key DROP NOT NULL,
    ALTER COLUMN issue_url DROP NOT NULL;
