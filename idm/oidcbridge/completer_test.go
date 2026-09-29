// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"net/url"
	"testing"

	"github.com/pydio/cells/v5/common/auth/claim"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/common/proto/idm"
)

type fakeUserSyncer struct {
	user *idm.User
}

func (f fakeUserSyncer) Sync(context.Context, ExternalIdentity) (*idm.User, error) {
	return f.user, nil
}

type fakeCodeIssuer struct {
	claims     claim.Claims
	challenge  string
	requestURL string
}

func (f *fakeCodeIssuer) Issue(_ context.Context, claims claim.Claims, challenge string) (*pauth.GetLoginResponse, string, error) {
	f.claims = claims
	f.challenge = challenge
	if f.requestURL != "" {
		return &pauth.GetLoginResponse{RequestURL: f.requestURL}, "cells-code", nil
	}
	return &pauth.GetLoginResponse{
		RequestURL: "https://files.example.com/oidc/auth?redirect_uri=" + url.QueryEscape("https://files.example.com/auth/callback?from=oidc") + "&state=cells-state",
	}, "cells-code", nil
}

func TestCellsCompleterCallbackDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, challenge, requestURL, want string
		wantErr                           bool
	}{
		{"internal browser flow", "", "https://files.example.com/oidc/auth", "/auth/callback?code=cells-code", false},
		{"CLI flow", "cli-challenge", "https://files.example.com/oidc/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fservers%2Fcallback&state=cli-state", "http://localhost:3000/servers/callback?code=cells-code&state=cli-state", false},
		{"malformed CLI flow", "cli-challenge", "https://files.example.com/oidc/auth", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakeCodeIssuer{requestURL: tc.requestURL}
			completer := NewCellsCompleter(fakeUserSyncer{user: &idm.User{Uuid: "user-uuid", Login: "alice"}}, issuer, "customer-oidc")
			got, err := completer.Complete(context.Background(), ExternalIdentity{Login: "alice"}, tc.challenge)
			if (err != nil) != tc.wantErr || got != tc.want || issuer.challenge != tc.challenge {
				t.Fatalf("got %q, err %v, challenge %q", got, err, issuer.challenge)
			}
		})
	}
}

func TestCellsCompleterIssuesCodeForSynchronizedUser(t *testing.T) {
	t.Parallel()

	issuer := &fakeCodeIssuer{}
	completer := NewCellsCompleter(
		fakeUserSyncer{user: &idm.User{Uuid: "user-uuid", Login: "alice", Attributes: map[string]string{"email": "alice@example.com"}}},
		issuer,
		"customer-oidc",
	)
	redirect, err := completer.Complete(context.Background(), ExternalIdentity{Login: "alice"}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/auth/callback" || parsed.Query().Get("from") != "oidc" || parsed.Query().Get("code") != "cells-code" || parsed.Query().Get("state") != "cells-state" {
		t.Fatalf("Complete() redirect = %q", redirect)
	}
	if issuer.claims.Subject != "user-uuid" || issuer.claims.Name != "alice" || issuer.claims.AuthSource != "customer-oidc" {
		t.Fatalf("issued claims = %#v", issuer.claims)
	}
}
