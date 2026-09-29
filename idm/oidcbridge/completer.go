// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pydio/cells/v5/common/auth"
	"github.com/pydio/cells/v5/common/auth/claim"
	"github.com/pydio/cells/v5/common/auth/hydra"
	"github.com/pydio/cells/v5/common/config"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/idm/oauth"
)

type CodeIssuer interface {
	Issue(ctx context.Context, claims claim.Claims, loginChallenge string) (*pauth.GetLoginResponse, string, error)
}

type defaultCodeIssuer struct{}

func (defaultCodeIssuer) Issue(ctx context.Context, claims claim.Claims, loginChallenge string) (*pauth.GetLoginResponse, string, error) {
	if loginChallenge != "" {
		return auth.DefaultJWTVerifier().LoginChallengeCode(ctx, claims, auth.SetChallenge(loginChallenge))
	}
	login, err := hydra.CreateLogin(ctx, config.DefaultOAuthClientID, []string{"openid", "profile", "offline"}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create Cells login flow: %w", err)
	}
	return auth.DefaultJWTVerifier().LoginChallengeCode(ctx, claims, auth.SetChallenge(login.GetChallenge()))
}

type CellsCompleter struct {
	users  UserSyncer
	codes  CodeIssuer
	source string
}

func NewCellsCompleter(users UserSyncer, codes CodeIssuer, source string) *CellsCompleter {
	if codes == nil {
		codes = defaultCodeIssuer{}
	}
	return &CellsCompleter{users: users, codes: codes, source: source}
}

func (c *CellsCompleter) Complete(ctx context.Context, identity ExternalIdentity, loginChallenge string) (string, error) {
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
	}, loginChallenge)
	if err != nil {
		return "", err
	}
	requestURL, err := url.Parse(login.GetRequestURL())
	if err != nil {
		return "", fmt.Errorf("parse Cells login request URL: %w", err)
	}
	redirectURI, err := oauth.GetRedirectURIFromRequestValues(requestURL.Query())
	if err != nil {
		return "", fmt.Errorf("resolve Cells callback URL: %w", err)
	}
	if redirectURI == "" {
		if loginChallenge != "" {
			return "", fmt.Errorf("Cells client login has no callback URL")
		}
		// CreateLogin produces an internal flow without redirect_uri. The
		// native browser code exchanger lives at this same-origin route.
		redirectURI = "/auth/callback"
	}
	target, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse Cells callback URL: %w", err)
	}
	query := target.Query()
	query.Set("code", code)
	if state := requestURL.Query().Get("state"); state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}
