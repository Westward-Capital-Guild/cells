// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pydio/cells/v5/common/auth"
	"github.com/pydio/cells/v5/common/auth/claim"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/idm/oauth"
)

type CodeIssuer interface {
	Issue(ctx context.Context, claims claim.Claims) (*pauth.GetLoginResponse, string, error)
}

type defaultCodeIssuer struct{}

func (defaultCodeIssuer) Issue(ctx context.Context, claims claim.Claims) (*pauth.GetLoginResponse, string, error) {
	return auth.DefaultJWTVerifier().LoginChallengeCode(ctx, claims)
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
	redirectURI, err := oauth.GetRedirectURIFromRequestValues(requestURL.Query())
	if err != nil {
		return "", fmt.Errorf("resolve Cells callback URL: %w", err)
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
