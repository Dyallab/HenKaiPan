package validation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DefaultAllowedGitHosts are the only git providers allowed as scan targets.
var DefaultAllowedGitHosts = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
}

// ValidateGitTarget checks that a scan target is a safe, allowed git URL.
// Returns an error describing the problem if the target is rejected.
func ValidateGitTarget(raw string) error {
	if raw == "" {
		return fmt.Errorf("target is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid target URL")
	}

	// Only allow https scheme — reject git://, ssh://, http://, file://, etc.
	if parsed.Scheme != "https" {
		return fmt.Errorf("target must use https scheme")
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("invalid target URL: no host")
	}

	// Fast path: host is in the allowlist
	if DefaultAllowedGitHosts[host] {
		return nil
	}

	// Block localhost variants
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("target must not be localhost")
	}

	// Block private/reserved IP literals
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("target must be a public address")
		}
		return fmt.Errorf("target host IP is not in the allowed git providers list")
	}

	return fmt.Errorf("target host '%s' is not in the allowed git providers list (github.com, gitlab.com, bitbucket.org)", host)
}
