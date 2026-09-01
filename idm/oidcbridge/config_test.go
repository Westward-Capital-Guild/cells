// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	valid := Config{
		IssuerURL:     "https://id.example.com/realms/customer",
		ClientID:      "cells",
		ClientSecret:  "secret",
		RedirectURL:   "https://files.example.com/auth/oidc/callback",
		Scopes:        []string{"openid", "profile", "email"},
		UsernameClaim: "preferred_username",
		Source:        "customer-oidc",
		FlowTTL:       5 * time.Minute,
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "missing issuer", mutate: func(c *Config) { c.IssuerURL = "" }, wantErr: "issuer"},
		{name: "insecure issuer", mutate: func(c *Config) { c.IssuerURL = "http://id.example.com" }, wantErr: "HTTPS"},
		{name: "issuer query", mutate: func(c *Config) { c.IssuerURL += "?tenant=one" }, wantErr: "query"},
		{name: "issuer credentials", mutate: func(c *Config) { c.IssuerURL = "https://user:pass@id.example.com" }, wantErr: "credentials"},
		{name: "missing client id", mutate: func(c *Config) { c.ClientID = "" }, wantErr: "client ID"},
		{name: "missing client secret", mutate: func(c *Config) { c.ClientSecret = "" }, wantErr: "client secret"},
		{name: "insecure redirect", mutate: func(c *Config) { c.RedirectURL = "http://files.example.com/auth/oidc/callback" }, wantErr: "HTTPS"},
		{name: "redirect fragment", mutate: func(c *Config) { c.RedirectURL += "#fragment" }, wantErr: "fragment"},
		{name: "missing openid scope", mutate: func(c *Config) { c.Scopes = []string{"profile", "email"} }, wantErr: "openid"},
		{name: "missing username claim", mutate: func(c *Config) { c.UsernameClaim = "" }, wantErr: "username claim"},
		{name: "missing source", mutate: func(c *Config) { c.Source = "" }, wantErr: "source"},
		{name: "short flow ttl", mutate: func(c *Config) { c.FlowTTL = 30 * time.Second }, wantErr: "flow TTL"},
		{name: "long flow ttl", mutate: func(c *Config) { c.FlowTTL = 20 * time.Minute }, wantErr: "flow TTL"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigAllowsLoopbackHTTPForSyntheticPoC(t *testing.T) {
	t.Parallel()

	cfg := Config{
		IssuerURL:     "http://127.0.0.1:5556/oidc",
		ClientID:      "cells",
		ClientSecret:  "secret",
		RedirectURL:   "http://localhost:8080/auth/oidc/callback",
		Scopes:        []string{"openid"},
		UsernameClaim: "preferred_username",
		Source:        "customer-oidc",
		FlowTTL:       5 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected loopback PoC endpoints: %v", err)
	}
}
