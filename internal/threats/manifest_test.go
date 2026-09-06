package threats

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func mustManifestFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func sortManifestDeps(deps []Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		return deps[i].Name < deps[j].Name
	})
}

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name       string
		sourceFile string
		fixture    string
		inline     []byte // used instead of fixture when non-nil
		want       []Dependency
		wantErr    bool
	}{
		{
			name:       "package.json keeps exact pins, skips ranges",
			sourceFile: "package.json",
			fixture:    "package.json",
			want: []Dependency{
				{Ecosystem: "npm", Name: "express", Version: "4.18.2", SourceFile: "package.json"},
			},
		},
		{
			name:       "package.json caret range skipped",
			sourceFile: "package.json",
			inline:     []byte(`{"dependencies": {"lodash": "^4.17.21"}}`),
			want:       nil,
		},
		{
			name:       "package.json tilde range skipped",
			sourceFile: "package.json",
			inline:     []byte(`{"dependencies": {"lodash": "~4.17.21"}}`),
			want:       nil,
		},
		{
			name:       "package.json gte complex range skipped",
			sourceFile: "package.json",
			inline:     []byte(`{"dependencies": {"ts": ">=1.0.0 <2.0.0"}}`),
			want:       nil,
		},
		{
			name:       "package.json comparator, star, dist-tag, URL and union ranges skipped",
			sourceFile: "package.json",
			inline:     []byte(`{"dependencies": {"a": ">1.0.0", "b": "<2.0.0", "c": "*", "d": "latest", "e": "https://example.com/a.tgz", "f": "1.0.0 || 2.0.0", "g": "1.2.3 - 2.3.4"}}`),
			want:       nil,
		},
		{
			name:       "package.json exact and = pins kept",
			sourceFile: "package.json",
			inline:     []byte(`{"dependencies": {"lodash": "4.17.21", "express": "=4.18.2"}}`),
			want: []Dependency{
				{Ecosystem: "npm", Name: "express", Version: "4.18.2", SourceFile: "package.json"},
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", SourceFile: "package.json"},
			},
		},
		{
			name:       "go.mod require blocks skip indirect",
			sourceFile: "go.mod",
			fixture:    "go.mod",
			want: []Dependency{
				{Ecosystem: "go", Name: "github.com/go-chi/chi/v5", Version: "v5.0.1", SourceFile: "go.mod"},
				{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "v0.22.0", SourceFile: "go.mod"},
			},
		},
		{
			name:       "requirements.txt pinned, extras, skips ranges",
			sourceFile: "requirements.txt",
			fixture:    "requirements.txt",
			want: []Dependency{
				{Ecosystem: "pip", Name: "django", Version: "4.2.7", SourceFile: "requirements.txt"},
				{Ecosystem: "pip", Name: "requests", Version: "2.31.0", SourceFile: "requirements.txt"},
				{Ecosystem: "pip", Name: "uvicorn", Version: "0.24.0", SourceFile: "requirements.txt"},
			},
		},
		{
			name:       "Cargo.lock packages",
			sourceFile: "Cargo.lock",
			fixture:    "Cargo.lock",
			want: []Dependency{
				{Ecosystem: "cargo", Name: "serde", Version: "1.0.197", SourceFile: "Cargo.lock"},
				{Ecosystem: "cargo", Name: "tokio", Version: "1.37.0", SourceFile: "Cargo.lock"},
			},
		},
		{
			name:       "malformed package.json returns error",
			sourceFile: "package.json",
			inline:     []byte(`{not valid json`),
			wantErr:    true,
		},
		{
			name:       "malformed go.mod returns error",
			sourceFile: "go.mod",
			inline:     []byte("module example.com/demo\nrequire (\n"),
			wantErr:    true,
		},
		{
			name:       "malformed Cargo.lock returns error",
			sourceFile: "Cargo.lock",
			inline:     []byte("[[package]]\nname = \n"),
			wantErr:    true,
		},
		{
			name:       "unknown manifest returns error",
			sourceFile: "Gemfile",
			inline:     []byte(`source "https://rubygems.org"`),
			wantErr:    true,
		},
		{
			name:       "empty input returns error not panic",
			sourceFile: "package.json",
			inline:     []byte{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			if tt.inline != nil {
				data = tt.inline
			} else {
				data = mustManifestFixture(t, tt.fixture)
			}
			got, err := ParseManifest(tt.sourceFile, data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseManifest(%q) expected error, got nil with %v", tt.sourceFile, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseManifest(%q) unexpected error: %v", tt.sourceFile, err)
			}
			sortManifestDeps(got)
			sortManifestDeps(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseManifest(%q) mismatch:\n got: %+v\nwant: %+v", tt.sourceFile, got, tt.want)
			}
		})
	}
}

func TestOSVEcosystem(t *testing.T) {
	cases := map[string]string{
		"npm":   "npm",
		"go":    "Go",
		"pip":   "PyPI",
		"cargo": "crates.io",
	}
	for in, want := range cases {
		if got := OSVEcosystem(in); got != want {
			t.Errorf("OSVEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
	if got := OSVEcosystem("rubygems"); got != "" {
		t.Errorf("OSVEcosystem(rubygems) = %q, want empty", got)
	}
}
