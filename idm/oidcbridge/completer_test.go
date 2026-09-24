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
	claims claim.Claims
}

func (f *fakeCodeIssuer) Issue(_ context.Context, claims claim.Claims) (*pauth.GetLoginResponse, string, error) {
	f.claims = claims
	return &pauth.GetLoginResponse{
		RequestURL: "https://files.example.com/oidc/auth?state=cells-state",
	}, "cells-code", nil
}

func TestCellsCompleterIssuesCodeForSynchronizedUser(t *testing.T) {
	t.Parallel()

	issuer := &fakeCodeIssuer{}
	completer := NewCellsCompleter(
		fakeUserSyncer{user: &idm.User{Uuid: "user-uuid", Login: "alice", Attributes: map[string]string{"email": "alice@example.com"}}},
		issuer,
		"customer-oidc",
		"https://files.example.com/auth/callback?from=oidc",
	)
	redirect, err := completer.Complete(context.Background(), ExternalIdentity{Login: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/login/callback" || parsed.Query().Get("from") != "oidc" || parsed.Query().Get("code") != "cells-code" || parsed.Query().Get("state") != "cells-state" {
		t.Fatalf("Complete() redirect = %q", redirect)
	}
	if issuer.claims.Subject != "user-uuid" || issuer.claims.Name != "alice" || issuer.claims.AuthSource != "customer-oidc" {
		t.Fatalf("issued claims = %#v", issuer.claims)
	}
}
