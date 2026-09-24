// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/pydio/cells/v5/common/auth"
	"github.com/pydio/cells/v5/common/auth/claim"
	"github.com/pydio/cells/v5/common/auth/hydra"
	"github.com/pydio/cells/v5/common/config"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
)

type CodeIssuer interface {
	Issue(ctx context.Context, claims claim.Claims) (*pauth.GetLoginResponse, string, error)
}

type defaultCodeIssuer struct{}

func (defaultCodeIssuer) Issue(ctx context.Context, claims claim.Claims) (*pauth.GetLoginResponse, string, error) {
	login, err := hydra.CreateLogin(ctx, config.DefaultOAuthClientID, []string{"openid", "profile", "offline"}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create Cells login flow: %w", err)
	}
	return auth.DefaultJWTVerifier().LoginChallengeCode(ctx, claims, auth.SetChallenge(login.GetChallenge()))
}

type CellsCompleter struct {
	users       UserSyncer
	codes       CodeIssuer
	source      string
	callbackURL string
}

func NewCellsCompleter(users UserSyncer, codes CodeIssuer, source, callbackURL string) *CellsCompleter {
	if codes == nil {
		codes = defaultCodeIssuer{}
	}
	return &CellsCompleter{users: users, codes: codes, source: source, callbackURL: callbackURL}
}

func (c *CellsCompleter) Complete(ctx context.Context, identity ExternalIdentity) (string, error) {
	user, err := c.users.Sync(ctx, identity)
	if err != nil {
		return "", err
	}
	login, code, err := c.codes.Issue(ctx, claim.Claims{
		Subject:     user.GetUuid(),
		Name:        user.GetLogin(),
		Email:       user.GetAttributes()["email"],
		DisplayName: user.GetAttributes()["name"],
		AuthSource:  c.source,
	})
	if err != nil {
		return "", err
	}
	requestURL, err := url.Parse(login.GetRequestURL())
	if err != nil {
		return "", fmt.Errorf("parse Cells login request URL: %w", err)
	}
	target, err := url.Parse(c.callbackURL)
	if err != nil {
		return "", fmt.Errorf("parse Cells callback URL: %w", err)
	}
	// Cells exchanges the code against /auth/callback, but its browser handler lives at /login/callback.
	if !strings.HasSuffix(target.Path, "/auth/callback") {
		return "", fmt.Errorf("unexpected Cells callback path %q", target.Path)
	}
	target.Path = strings.TrimSuffix(target.Path, "/auth/callback") + "/login/callback"
	query := target.Query()
	query.Set("code", code)
	if state := requestURL.Query().Get("state"); state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}
