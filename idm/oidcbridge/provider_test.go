// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestProviderClientAuthorizationURLIncludesNonceAndPKCE(t *testing.T) {
	t.Parallel()

	client := &ProviderClient{oauthConfig: oauth2.Config{
		ClientID:    "cells",
		RedirectURL: "https://files.example.com/auth/oidc/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://id.example.com/authorize",
		},
		Scopes: []string{"openid", "profile", "email"},
	}}
	redirect, err := url.Parse(client.AuthorizationURL("state", "nonce", "verifier"))
	if err != nil {
		t.Fatal(err)
	}
	query := redirect.Query()
	if query.Get("state") != "state" || query.Get("nonce") != "nonce" {
		t.Fatalf("authorization URL missing state or nonce: %s", redirect)
	}
	if query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier("verifier") || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL missing PKCE S256: %s", redirect)
	}
}
