// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/pydio/cells/v5/common/telemetry/log"
)

type OIDCClient interface {
	AuthorizationURL(state, nonce, pkceVerifier string) string
	ExchangeAndVerify(ctx context.Context, code, nonce, pkceVerifier string) (ExternalIdentity, error)
}

type LoginCompleter interface {
	Complete(ctx context.Context, identity ExternalIdentity, loginChallenge string) (redirectURL string, err error)
}

type Handler struct {
	client    OIDCClient
	completer LoginCompleter
	flows     *FlowStore
}

func NewHandler(client OIDCClient, completer LoginCompleter, flows *FlowStore) *Handler {
	return &Handler{client: client, completer: completer, flows: flows}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch r.URL.Path {
	case "/login":
		h.login(w, r)
	case "/callback":
		h.callback(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flow, err := h.flows.Begin(r.URL.Query().Get("login_challenge"))
	if err != nil {
		http.Error(w, "could not start OIDC login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.client.AuthorizationURL(flow.State, flow.Nonce, flow.PKCEVerifier), http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "OIDC provider rejected the login", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing OIDC callback parameters", http.StatusBadRequest)
		return
	}
	flow, err := h.flows.Consume(state)
	if err != nil {
		http.Error(w, "invalid or expired OIDC login", http.StatusBadRequest)
		return
	}
	identity, err := h.client.ExchangeAndVerify(r.Context(), code, flow.Nonce, flow.PKCEVerifier)
	if err != nil {
		log.Logger(r.Context()).Warn("Customer OIDC verification failed", zap.Error(err))
		http.Error(w, "OIDC login verification failed", http.StatusUnauthorized)
		return
	}
	redirectURL, err := h.completer.Complete(r.Context(), identity, flow.LoginChallenge)
	if err != nil {
		log.Logger(r.Context()).Warn("Customer OIDC Cells login completion failed", zap.Error(err))
		http.Error(w, "could not complete Cells login", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
