package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/flow"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/x/sqlxx"

	"github.com/pydio/cells/v5/common/config"
	"github.com/pydio/cells/v5/common/config/routing"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/common/proto/install"
	"github.com/pydio/cells/v5/common/runtime/manager"
	"github.com/pydio/cells/v5/common/storage/test"
	"github.com/pydio/cells/v5/common/utils/uuid"
	"github.com/pydio/cells/v5/idm/oauth"
	sqldao "github.com/pydio/cells/v5/idm/oauth/dao/sql"
)

func TestLoginChallengeCodePreservesNonce(t *testing.T) {
	test.RunStorageTests(test.TemplateSQL(sqldao.NewRegistryDAO), t, func(ctx context.Context) {
		t.Run("authorization", func(t *testing.T) {
			site := &install.ProxyConfig{Binds: []string{"nonce-test.invalid:443"}, ReverseProxyURL: "https://nonce-test.invalid"}
			if err := config.Set(ctx, []*install.ProxyConfig{site}, routing.ConfigPath...); err != nil {
				t.Fatal(err)
			}
			var err error
			ctx, err = routing.SiteToContext(ctx, site)
			if err != nil {
				t.Fatal(err)
			}
			cli := &client.Client{ID: "cells-client", RedirectURIs: []string{"http://localhost:3000/servers/callback"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, Scope: "openid profile", TokenEndpointAuthMethod: "none"}
			if err := config.Set(ctx, map[string]any{"secret": "0123456789abcdef0123456789abcdef", "staticClients": []*client.Client{cli}}, oauth.ConfigCorePath...); err != nil {
				t.Fatal(err)
			}
			reg, err := manager.Resolve[oauth.Registry](ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name          string
				nonce         string
				wrongVerifier bool
			}{
				{name: "original nonce", nonce: "original-cli-authorization-nonce-12345678"},
				{name: "optional nonce omitted"},
				{name: "short nonce rejected", nonce: "short"},
				{name: "wrong PKCE verifier rejected", nonce: "original-cli-authorization-nonce-12345678", wrongVerifier: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					verifier := strings.Repeat("v", 64)
					hash := sha256.Sum256([]byte(verifier))
					challenge := base64.RawURLEncoding.EncodeToString(hash[:])
					nonce := tc.nonce
					params := url.Values{"client_id": {cli.ID}, "redirect_uri": {cli.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid profile"}, "state": {"original-cli-state-12345678"}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
					if nonce == "" {
						params.Del("nonce")
					}
					sessionID := uuid.New()
					if err := reg.ConsentManager().CreateLoginSession(ctx, &flow.LoginSession{ID: sessionID}); err != nil {
						t.Fatal(err)
					}
					f, err := reg.ConsentManager().CreateLoginRequest(ctx, &flow.LoginRequest{ID: uuid.New(), Verifier: uuid.New(), CSRF: uuid.New(), RequestedScope: []string{"openid", "profile"}, ClientID: cli.ID, Client: cli, RequestURL: "https://nonce-test.invalid/oidc/oauth2/auth?" + params.Encode(), RequestedAt: time.Now().UTC(), SessionID: sqlxx.NullString(sessionID)})
					if err != nil {
						t.Fatal(err)
					}
					loginChallenge, err := f.ToLoginChallenge(ctx, reg)
					if err != nil {
						t.Fatal(err)
					}
					result, err := NewOAuthGRPCHandler().LoginChallengeCode(ctx, &pauth.LoginChallengeCodeRequest{Challenge: loginChallenge, Claims: map[string]string{"subject": "test-user", "name": "test-user", "authSource": "test"}})
					if err != nil {
						t.Fatalf("create authorization code: %v", err)
					}
					values := url.Values{"client_id": {cli.ID}, "grant_type": {"authorization_code"}, "code": {result.Code}, "redirect_uri": {cli.RedirectURIs[0]}, "code_verifier": {verifier}}
					if tc.wrongVerifier {
						values.Set("code_verifier", strings.Repeat("w", 64))
					}
					req, err := http.NewRequestWithContext(ctx, "POST", "https://nonce-test.invalid/oidc/oauth2/token", strings.NewReader(values.Encode()))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					ar, err := reg.OAuth2Provider().NewAccessRequest(ctx, req, oauth2.NewSessionWithCustomClaims(ctx, reg.Config(), ""))
					if tc.wrongVerifier {
						if !errors.Is(err, fosite.ErrInvalidGrant) {
							t.Fatalf("wrong verifier: got %v, want invalid_grant", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("exchange code: %v", err)
					}
					response, err := reg.OAuth2Provider().NewAccessResponse(ctx, ar)
					if nonce == "short" {
						if !errors.Is(err, fosite.ErrInsufficientEntropy) {
							t.Fatalf("short nonce: got %v, want insufficient entropy", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					idToken, ok := response.GetExtra("id_token").(string)
					if !ok {
						t.Fatal("missing ID token")
					}
					verified, err := reg.OpenIDJWTStrategy().Decode(ctx, idToken)
					if err != nil {
						t.Fatalf("verify ID token signature: %v", err)
					}
					if got, _ := verified.Claims["nonce"].(string); got != nonce {
						t.Fatalf("ID token nonce = %v, want original authorization nonce", got)
					}
					replay, err := http.NewRequestWithContext(ctx, "POST", "https://nonce-test.invalid/oidc/oauth2/token", strings.NewReader(values.Encode()))
					if err != nil {
						t.Fatal(err)
					}
					replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if _, err := reg.OAuth2Provider().NewAccessRequest(ctx, replay, oauth2.NewSessionWithCustomClaims(ctx, reg.Config(), "")); err == nil {
						t.Fatal("authorization code replay unexpectedly succeeded")
					}
				})
			}
		})
	})
}
