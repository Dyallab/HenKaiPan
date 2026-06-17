package validation

import (
	"testing"

	"aspm/internal/assert"
)

func TestValidateGitTarget_ValidHosts(t *testing.T) {
	tests := []string{
		"https://github.com/owner/repo.git",
		"https://github.com/owner/repo",
		"https://github.com/owner/repo/issues/1",
		"https://gitlab.com/owner/repo.git",
		"https://gitlab.com/owner/repo",
		"https://bitbucket.org/owner/repo.git",
		"https://bitbucket.org/owner/repo",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.Nil(t, ValidateGitTarget(tt))
		})
	}
}

func TestValidateGitTarget_InvalidScheme(t *testing.T) {
	tests := []string{
		"http://github.com/owner/repo.git",
		"git@github.com:owner/repo.git",
		"git://github.com/owner/repo.git",
		"ssh://git@github.com/owner/repo.git",
		"file:///path/to/repo",
		"ftp://github.com/owner/repo.git",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.NotNil(t, ValidateGitTarget(tt))
		})
	}
}

func TestValidateGitTarget_BlockedHosts(t *testing.T) {
	tests := []struct {
		url     string
		desc    string
	}{
		{"https://evil.com/repo.git", "non-allowed host"},
		{"https://random-site.net/owner/repo", "random domain"},
		{"https://my-gitlab-instance.com/repo", "self-hosted gitlab"},
		{"https://githubb.com/repo", "typosquatting"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert.NotNil(t, ValidateGitTarget(tt.url))
		})
	}
}

func TestValidateGitTarget_Localhost(t *testing.T) {
	tests := []string{
		"https://localhost/repo.git",
		"https://localhost.localdomain/repo.git",
		"https://foo.localhost/repo.git",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.NotNil(t, ValidateGitTarget(tt))
		})
	}
}

func TestValidateGitTarget_PrivateIPs(t *testing.T) {
	tests := []string{
		"https://10.0.0.1/repo.git",
		"https://172.16.0.1/repo.git",
		"https://192.168.1.1/repo.git",
		"https://127.0.0.1/repo.git",
		"https://169.254.1.1/repo.git",
		"https://0.0.0.0/repo.git",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.NotNil(t, ValidateGitTarget(tt))
		})
	}
}

func TestValidateGitTarget_Empty(t *testing.T) {
	assert.NotNil(t, ValidateGitTarget(""))
}

func TestValidateGitTarget_InvalidURL(t *testing.T) {
	tests := []string{
		"not-a-url",
		"https://",
		":",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.NotNil(t, ValidateGitTarget(tt))
		})
	}
}
