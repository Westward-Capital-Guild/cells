// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"testing"
)

func TestSubjectUUIDUsesExactIssuerAndSubject(t *testing.T) {
	t.Parallel()

	a, err := SubjectUUID("https://id.example.com/tenant-a", "user-42")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SubjectUUID("https://id.example.com/tenant-a", "user-42")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("SubjectUUID() is not deterministic: %q != %q", a, b)
	}

	otherIssuer, _ := SubjectUUID("https://id.example.com/tenant-b", "user-42")
	otherSubject, _ := SubjectUUID("https://id.example.com/tenant-a", "user-43")
	if a == otherIssuer || a == otherSubject {
		t.Fatal("SubjectUUID() merged distinct OIDC subjects")
	}
}

func TestSubjectUUIDRejectsIncompleteIdentity(t *testing.T) {
	t.Parallel()

	if _, err := SubjectUUID("", "user-42"); err == nil {
		t.Fatal("SubjectUUID() accepted an empty issuer")
	}
	if _, err := SubjectUUID("https://id.example.com", ""); err == nil {
		t.Fatal("SubjectUUID() accepted an empty subject")
	}
}

func TestMapIdentityUsesConfiguredClaims(t *testing.T) {
	t.Parallel()

	identity, err := MapIdentity(
		"https://id.example.com/tenant-a",
		"user-42",
		map[string]any{
			"preferred_username": "alice",
			"mail":               "alice@example.com",
			"display_name":       "Alice Example",
			"groups":             []any{"finance", "reviewers"},
		},
		ClaimMapping{
			Username:    "preferred_username",
			Email:       "mail",
			DisplayName: "display_name",
			Groups:      "groups",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Login != "alice" || identity.Email != "alice@example.com" || identity.DisplayName != "Alice Example" {
		t.Fatalf("MapIdentity() = %#v", identity)
	}
	if len(identity.Groups) != 2 || identity.Groups[0] != "finance" || identity.Groups[1] != "reviewers" {
		t.Fatalf("MapIdentity() groups = %#v", identity.Groups)
	}
}

func TestMapIdentityRejectsUnsafeOrMissingLogin(t *testing.T) {
	t.Parallel()

	for _, login := range []string{"", "group/alice"} {
		_, err := MapIdentity(
			"https://id.example.com/tenant-a",
			"user-42",
			map[string]any{"preferred_username": login},
			ClaimMapping{Username: "preferred_username"},
		)
		if err == nil {
			t.Fatalf("MapIdentity() accepted login %q", login)
		}
	}
}
