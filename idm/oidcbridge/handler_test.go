// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type fakeOIDCClient struct {
	authorizationURL string
	callbackIdentity ExternalIdentity
	wantNonce        string
	wantVerifier     string
}

func (f *fakeOIDCClient) AuthorizationURL(state, nonce, pkceChallenge string) string {
	u, _ := url.Parse(f.authorizationURL)
	q := u.Query()
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge)
	u.RawQuery = q.Encode()
	return u.String()
}

func (f *fakeOIDCClient) ExchangeAndVerify(_ context.Context, code, nonce, pkceVerifier string) (ExternalIdentity, error) {
	f.wantNonce = nonce
	f.wantVerifier = pkceVerifier
	return f.callbackIdentity, nil
}

type fakeCompleter struct {
	identity ExternalIdentity
}

func (f *fakeCompleter) Complete(_ context.Context, identity ExternalIdentity) (string, error) {
	f.identity = identity
	return "/auth/callback?code=cells-code", nil
}

func TestHandlerCompletesOneTimeOIDCFlow(t *testing.T) {
	t.Parallel()

	client := &fakeOIDCClient{
		authorizationURL: "https://id.example.com/authorize",
		callbackIdentity: ExternalIdentity{
			Issuer:  "https://id.example.com",
			Subject: "user-42",
			Login:   "alice",
		},
	}
	completer := &fakeCompleter{}
	handler := NewHandler(client, completer, NewFlowStore(5*time.Minute, time.Now))

	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginResponse.Code, http.StatusFound)
	}
	if loginResponse.Header().Get("Cache-Control") != "no-store" || loginResponse.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("login response missing security headers: %#v", loginResponse.Header())
	}
	authorizeURL, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizeURL.Query().Get("state")
	if state == "" || authorizeURL.Query().Get("nonce") == "" || authorizeURL.Query().Get("code_challenge") == "" {
		t.Fatalf("login redirect missing security parameters: %s", authorizeURL)
	}

	callbackResponse := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=upstream-code&state="+url.QueryEscape(state), nil)
	handler.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %q", callbackResponse.Code, callbackResponse.Body.String())
	}
	if callbackResponse.Header().Get("Location") != "/auth/callback?code=cells-code" {
		t.Fatalf("callback redirect = %q", callbackResponse.Header().Get("Location"))
	}
	if completer.identity.Login != "alice" || client.wantNonce == "" || client.wantVerifier == "" {
		t.Fatalf("callback was not completed securely: identity=%#v nonce=%q verifier=%q", completer.identity, client.wantNonce, client.wantVerifier)
	}

	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, callbackRequest)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want %d", replayResponse.Code, http.StatusBadRequest)
	}
}

func TestHandlerRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := NewHandler(&fakeOIDCClient{}, &fakeCompleter{}, NewFlowStore(5*time.Minute, time.Now))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/login", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}
