package db

import (
	"strings"
	"testing"
)

func TestSplitSQLStatements(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "simple statements",
			sql:  "ALTER TABLE t ADD COLUMN a TEXT;\nALTER TABLE t ADD COLUMN b TEXT;",
			want: []string{
				"ALTER TABLE t ADD COLUMN a TEXT",
				"ALTER TABLE t ADD COLUMN b TEXT",
			},
		},
		{
			name: "line comment with semicolon",
			sql:  "-- this; is a comment\nSELECT 1;",
			want: []string{
				"-- this; is a comment\nSELECT 1",
			},
		},
		{
			name: "block comment with semicolon",
			sql:  "/* this; is a comment */\nSELECT 1;",
			want: []string{
				"/* this; is a comment */\nSELECT 1",
			},
		},
		{
			name: "string literal with semicolon",
			sql:  "INSERT INTO t VALUES ('a;b');\nSELECT 2;",
			want: []string{
				"INSERT INTO t VALUES ('a;b')",
				"SELECT 2",
			},
		},
		{
			name: "dollar quoted string with semicolon",
			sql:  "DO $$ BEGIN RAISE NOTICE 'a;b'; END $$;\nSELECT 3;",
			want: []string{
				"DO $$ BEGIN RAISE NOTICE 'a;b'; END $$",
				"SELECT 3",
			},
		},
		{
			name: "escaped single quote",
			sql:  "INSERT INTO t VALUES ('it''s');\nSELECT 4;",
			want: []string{
				"INSERT INTO t VALUES ('it''s')",
				"SELECT 4",
			},
		},
		{
			name: "no trailing semicolon",
			sql:  "SELECT 5",
			want: []string{"SELECT 5"},
		},
		{
			name: "empty input",
			sql:  "",
			want: nil,
		},
		{
			name: "migration 047 shape",
			sql: `-- NO TRANSACTION
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_sso_identity
    ON users (sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL;`,
			want: []string{
				"-- NO TRANSACTION\nALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT",
				"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_sso_identity\n    ON users (sso_provider, sso_subject)\n    WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitSQLStatements(tt.sql)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d statements, want %d:\n%#v", len(got), len(tt.want), got)
			}
			for i := range got {
				if strings.TrimSpace(got[i]) != strings.TrimSpace(tt.want[i]) {
					t.Errorf("statement %d:\n got: %q\nwant: %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
