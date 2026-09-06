package tasks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"aspm/internal/models"
	"aspm/internal/threats"
)

func threatFetchTestProject(repoURL, branch string) models.Project {
	p := models.Project{ID: "proj-1", Name: "p1", DefaultBranch: branch}
	if repoURL != "" {
		u := repoURL
		p.RepoURL = &u
	}
	return p
}

// Found manifest: first well-known path hit returns (sourceFile, bytes)
// that ParseManifest can dispatch on, with the project token forwarded.
func TestThreatFetchManifestFound(t *testing.T) {
	const manifest = `{"dependencies":{"lodash":"4.17.21"}}`
	var gotAuth, gotAccept, gotRef string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/web/contents/package.json" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotRef = r.URL.Query().Get("ref")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(manifest))
	}))
	defer srv.Close()

	src, data, err := fetchProjectManifest(context.Background(), srv.Client(), srv.URL,
		threatFetchTestProject("https://github.com/acme/web", "main"), "tok-123")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if src != "package.json" {
		t.Fatalf("sourceFile = %q, want package.json", src)
	}
	if string(data) != manifest {
		t.Fatalf("data = %q, want manifest body", data)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("Authorization = %q, want Bearer tok-123", gotAuth)
	}
	if gotAccept != "application/vnd.github.raw" {
		t.Fatalf("Accept = %q, want raw media type", gotAccept)
	}
	if gotRef != "main" {
		t.Fatalf("ref = %q, want main", gotRef)
	}
	// Fetched bytes must dispatch through ParseManifest first (sync flow).
	deps, err := threats.ParseManifest(src, data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "lodash" {
		t.Fatalf("deps = %+v, want [lodash]", deps)
	}
}

// First-found wins: package.json 404s, go.mod hit returns go.mod.
func TestThreatFetchManifestFirstFound(t *testing.T) {
	const gomod = "module example.com/web\n\nrequire github.com/foo/bar v1.2.3\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/web/contents/go.mod" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gomod))
	}))
	defer srv.Close()

	src, data, err := fetchProjectManifest(context.Background(), srv.Client(), srv.URL,
		threatFetchTestProject("git@github.com:acme/web.git", ""), "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if src != "go.mod" {
		t.Fatalf("sourceFile = %q, want go.mod", src)
	}
	if _, err := threats.ParseManifest(src, data); err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
}

// Missing manifests everywhere: typed skip (ErrNoManifestSource), not error.
func TestThreatFetchManifestMissingSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, _, err := fetchProjectManifest(context.Background(), srv.Client(), srv.URL,
		threatFetchTestProject("https://github.com/acme/empty", "main"), "")
	if !errors.Is(err, ErrNoManifestSource) {
		t.Fatalf("err = %v, want ErrNoManifestSource", err)
	}
}

// Non-GitHub projects skip without any HTTP request.
func TestThreatFetchManifestNonGitHubSkip(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cases := map[string]models.Project{
		"nil repo url":    {ID: "p-nil"},
		"empty repo url":  threatFetchTestProject("", "main"),
		"gitlab https":    threatFetchTestProject("https://gitlab.com/acme/web", "main"),
		"gitlab provider": {ID: "p-prov", Provider: "gitlab", RepoURL: strPtr("https://github.com/acme/web")},
		"unparseable":     threatFetchTestProject("not a repo ref !!!", "main"),
	}
	for name, p := range cases {
		_, _, err := fetchProjectManifest(context.Background(), srv.Client(), srv.URL, p, "")
		if !errors.Is(err, ErrNoManifestSource) {
			t.Fatalf("%s: err = %v, want ErrNoManifestSource", name, err)
		}
	}
	if hit {
		t.Fatal("non-github project caused an HTTP request")
	}
}

func TestThreatParseGitHubRepo(t *testing.T) {
	cases := []struct {
		name       string
		repoURL    string
		provider   string
		branch     string
		wantOwner  string
		wantRepo   string
		wantBranch string
		wantOK     bool
	}{
		{"https", "https://github.com/acme/web", "", "main", "acme", "web", "main", true},
		{"https git suffix", "https://github.com/acme/web.git", "", "", "acme", "web", "main", true},
		{"https custom branch", "https://github.com/acme/web", "", "develop", "acme", "web", "develop", true},
		{"https branch fragment", "https://github.com/acme/web#release", "", "", "acme", "web", "main", true},
		{"ssh", "git@github.com:acme/web.git", "", "", "acme", "web", "main", true},
		{"bare ref", "acme/web", "github", "", "acme", "web", "main", true},
		{"provider case", "https://github.com/acme/web", "GitHub", "", "acme", "web", "main", true},
		{"gitlab url", "https://gitlab.com/acme/web", "", "", "", "", "", false},
		{"gitlab provider", "https://github.com/acme/web", "gitlab", "", "", "", "", false},
		{"garbage", "not a repo ref !!!", "", "", "", "", "", false},
		{"trailing slash", "https://github.com/acme/web/", "", "", "acme", "web", "main", true},
	}
	for _, c := range cases {
		p := models.Project{ID: "p", Provider: c.provider, DefaultBranch: c.branch}
		if c.repoURL != "" {
			u := c.repoURL
			p.RepoURL = &u
		}
		owner, repo, branch, ok := parseGitHubRepo(p)
		if ok != c.wantOK {
			t.Fatalf("%s: ok = %v, want %v", c.name, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if owner != c.wantOwner || repo != c.wantRepo || branch != c.wantBranch {
			t.Fatalf("%s: got %s/%s@%s, want %s/%s@%s",
				c.name, owner, repo, branch, c.wantOwner, c.wantRepo, c.wantBranch)
		}
	}
	// Nil RepoURL skips.
	if _, _, _, ok := parseGitHubRepo(models.Project{ID: "p"}); ok {
		t.Fatal("nil RepoURL: ok = true, want false")
	}
	// Owner/repo with dot segments survive .git trimming only at the end.
	p := threatFetchTestProject("https://github.com/acme/web.go.git", "")
	if _, repo, _, ok := parseGitHubRepo(p); !ok || repo != "web.go" {
		t.Fatalf("dot repo: repo = %q ok = %v, want web.go true", repo, ok)
	}
	// Path with extra segments (tree/blob links) still resolves owner/repo.
	p = threatFetchTestProject("https://github.com/acme/web/tree/main/sub", "")
	if owner, repo, _, ok := parseGitHubRepo(p); !ok || owner != "acme" || repo != "web" {
		t.Fatalf("tree url: got %s/%s ok=%v", owner, repo, ok)
	}
}

func strPtr(s string) *string { return &s }
