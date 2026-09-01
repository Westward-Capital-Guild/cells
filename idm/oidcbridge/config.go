// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultFlowTTL = 5 * time.Minute
	MinimumFlowTTL = time.Minute
	MaximumFlowTTL = 15 * time.Minute
)

type Config struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	Scopes           []string
	UsernameClaim    string
	EmailClaim       string
	DisplayNameClaim string
	GroupsClaim      string
	Source           string
	FlowTTL          time.Duration
}

func (c Config) Validate() error {
	if err := validateEndpoint("issuer", c.IssuerURL, false); err != nil {
		return err
	}
	issuer, _ := url.Parse(c.IssuerURL)
	if issuer.RawQuery != "" {
		return fmt.Errorf("OIDC issuer URL must not contain a query")
	}
	if issuer.Fragment != "" {
		return fmt.Errorf("OIDC issuer URL must not contain a fragment")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("OIDC client ID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("OIDC client secret is required")
	}
	if err := validateEndpoint("redirect", c.RedirectURL, true); err != nil {
		return err
	}
	redirect, _ := url.Parse(c.RedirectURL)
	if redirect.Fragment != "" {
		return fmt.Errorf("OIDC redirect URL must not contain a fragment")
	}
	if !contains(c.Scopes, "openid") {
		return fmt.Errorf("OIDC scopes must include openid")
	}
	if strings.TrimSpace(c.UsernameClaim) == "" {
		return fmt.Errorf("OIDC username claim is required")
	}
	if strings.TrimSpace(c.Source) == "" {
		return fmt.Errorf("OIDC source is required")
	}
	if c.FlowTTL < MinimumFlowTTL || c.FlowTTL > MaximumFlowTTL {
		return fmt.Errorf("OIDC flow TTL must be between %s and %s", MinimumFlowTTL, MaximumFlowTTL)
	}
	return nil
}

func validateEndpoint(name, raw string, requirePath bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("OIDC %s URL is invalid", name)
	}
	if parsed.User != nil {
		return fmt.Errorf("OIDC %s URL must not contain credentials", name)
	}
	if requirePath && (parsed.Path == "" || parsed.Path == "/") {
		return fmt.Errorf("OIDC %s URL must include a path", name)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (host == "localhost" || isLoopback(host)) {
		return nil
	}
	return fmt.Errorf("OIDC %s URL must use HTTPS outside loopback PoC environments", name)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Config) Mapping() ClaimMapping {
	return ClaimMapping{
		Username:    c.UsernameClaim,
		Email:       c.EmailClaim,
		DisplayName: c.DisplayNameClaim,
		Groups:      c.GroupsClaim,
	}
}
