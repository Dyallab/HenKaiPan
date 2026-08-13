package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider wraps an OIDC provider and its OAuth2 configuration.
// It handles the login redirect, callback exchange, and ID token verification.
type Provider struct {
	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
	issuer       string
	groupClaim   string
	adminGroup   string
}

// Claims represents the identity information extracted from an OIDC ID token.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name            string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups          []string `json:"groups"`
}

// NewProvider creates a new SSO Provider by discovering the OIDC configuration
// at the given issuer URL. Must be called at startup (or on first use) since
// it makes an HTTP request to the IdP's well-known endpoint.
func NewProvider(ctx context.Context, issuer, clientID, clientSecret, redirectURI, groupClaim, adminGroup string) (*Provider, error) {
	if issuer == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, fmt.Errorf("issuer, client_id, client_secret, and redirect_uri are required")
	}

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}

	if groupClaim == "" {
		groupClaim = "groups"
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.Endpoint(),
		// Request the groups scope so group membership is available in the
		// ID token (used for role mapping via SSO_ADMIN_GROUP). Some IdPs
		// require the client to explicitly request this scope.
		Scopes: []string{oidc.ScopeOpenID, "email", "profile", "groups"},
	}

	return &Provider{
		oidcProvider: p,
		oauth2Config: oauth2Config,
		issuer:       issuer,
		groupClaim:   groupClaim,
		adminGroup:   adminGroup,
	}, nil
}

// Issuer returns the OIDC issuer URL, used as the unique provider identifier
// when storing SSO identity links on user records.
func (p *Provider) Issuer() string {
	return p.issuer
}

// AuthURL returns the OIDC authorization URL with the given state parameter.
func (p *Provider) AuthURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("prompt", "login"),
	)
}

// ExchangeAndVerify exchanges the authorization code for tokens, verifies the
// ID token, and extracts claims including group membership.
//
// DECISION (2026-08-13): Claims come exclusively from the verified ID token.
// We deliberately do NOT fall back to the UserInfo endpoint. The IdP must be
// configured to include email/groups in the ID token (Authelia: claims_policy
// hydrating the id_token). Rationale: the UserInfo call adds a round-trip and
// trusts a second, unverified endpoint; the ID token alone is the audited,
// signed source of claims.
func (p *Provider) ExchangeAndVerify(ctx context.Context, code string) (*Claims, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code for token: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	verifier := p.oidcProvider.Verifier(&oidc.Config{
		ClientID: p.oauth2Config.ClientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse ID token claims: %w", err)
	}

	// Handle custom group claim names (e.g. "roles", "custom_claims").
	if p.groupClaim != "groups" && len(claims.Groups) == 0 {
		var all map[string]json.RawMessage
		if err := idToken.Claims(&all); err == nil {
			if raw, ok := all[p.groupClaim]; ok {
				var groups []string
				if json.Unmarshal(raw, &groups) == nil {
					claims.Groups = groups
				}
			}
		}
	}

	return &claims, nil
}

// ResolveRole maps the user's group membership to a HenKaiPan role
// ("admin" or "viewer"). If the user is in the admin group, returns "admin".
// Otherwise defaults to "viewer".
func (p *Provider) ResolveRole(claims *Claims) string {
	if p.adminGroup != "" {
		for _, g := range claims.Groups {
			if g == p.adminGroup {
				return "admin"
			}
		}
	}
	return "viewer"
}

// StateNonce is a short-lived nonce used to prevent CSRF on the OIDC callback.
type StateNonce struct {
	State   string
	Expires time.Time
}

// GenerateState creates a cryptographically random state string for CSRF protection.
func GenerateState() (StateNonce, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return StateNonce{}, fmt.Errorf("generate state: %w", err)
	}
	return StateNonce{
		State:   fmt.Sprintf("%x", b),
		Expires: time.Now().Add(5 * time.Minute),
	}, nil
}
