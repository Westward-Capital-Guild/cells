// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var subjectNamespace = uuid.MustParse("fe2c0b87-8b26-5e99-9654-2895c31ef61f")

type ClaimMapping struct {
	Username    string
	Email       string
	DisplayName string
	Groups      string
}

type ExternalIdentity struct {
	Issuer        string
	Subject       string
	UUID          string
	Login         string
	Email         string
	DisplayName   string
	EmailVerified bool
	Groups        []string
}

func SubjectUUID(issuer, subject string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if issuer == "" {
		return "", fmt.Errorf("OIDC issuer is required")
	}
	if subject == "" {
		return "", fmt.Errorf("OIDC subject is required")
	}
	return uuid.NewSHA1(subjectNamespace, []byte(issuer+"\x00"+subject)).String(), nil
}

func MapIdentity(issuer, subject string, claims map[string]any, mapping ClaimMapping) (ExternalIdentity, error) {
	id, err := SubjectUUID(issuer, subject)
	if err != nil {
		return ExternalIdentity{}, err
	}
	login := stringClaim(claims, mapping.Username)
	if login == "" {
		return ExternalIdentity{}, fmt.Errorf("OIDC claim %q must contain a non-empty login", mapping.Username)
	}
	if strings.Contains(login, "/") {
		return ExternalIdentity{}, fmt.Errorf("OIDC login must not contain a slash")
	}

	identity := ExternalIdentity{
		Issuer:      strings.TrimSpace(issuer),
		Subject:     strings.TrimSpace(subject),
		UUID:        id,
		Login:       login,
		Email:       stringClaim(claims, mapping.Email),
		DisplayName: stringClaim(claims, mapping.DisplayName),
		Groups:      stringSliceClaim(claims, mapping.Groups),
	}
	if verified, ok := claims["email_verified"].(bool); ok {
		identity.EmailVerified = verified
	}
	return identity, nil
}

func stringClaim(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	value, _ := claims[name].(string)
	return strings.TrimSpace(value)
}

func stringSliceClaim(claims map[string]any, name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	switch values := claims[name].(type) {
	case []string:
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				out = append(out, value)
			}
		}
	case []any:
		for _, raw := range values {
			if value, ok := raw.(string); ok {
				if value = strings.TrimSpace(value); value != "" {
					out = append(out, value)
				}
			}
		}
	}
	return out
}
