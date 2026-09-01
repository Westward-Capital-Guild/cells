// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type ProviderClient struct {
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
	mapping     ClaimMapping
}

func NewProviderClient(ctx context.Context, cfg Config) (*ProviderClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	return &ProviderClient{
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		mapping:  cfg.Mapping(),
	}, nil
}

func (c *ProviderClient) AuthorizationURL(state, nonce, pkceVerifier string) string {
	return c.oauthConfig.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
}

func (c *ProviderClient) ExchangeAndVerify(ctx context.Context, code, nonce, pkceVerifier string) (ExternalIdentity, error) {
	token, err := c.oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ExternalIdentity{}, fmt.Errorf("OIDC token response did not contain an ID token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return ExternalIdentity{}, fmt.Errorf("OIDC ID token nonce does not match the login flow")
	}
	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return ExternalIdentity{}, fmt.Errorf("decode OIDC ID token claims: %w", err)
	}
	return MapIdentity(idToken.Issuer, idToken.Subject, claims, c.mapping)
}
