// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/pydio/cells/v5/common/proto/idm"
)

type memoryDirectory struct {
	byUUID  map[string]*idm.User
	byLogin map[string]*idm.User
}

func newMemoryDirectory(users ...*idm.User) *memoryDirectory {
	d := &memoryDirectory{byUUID: map[string]*idm.User{}, byLogin: map[string]*idm.User{}}
	for _, user := range users {
		d.store(user)
	}
	return d
}

func (d *memoryDirectory) FindByUUID(_ context.Context, uuid string) (*idm.User, error) {
	if user, ok := d.byUUID[uuid]; ok {
		return proto.Clone(user).(*idm.User), nil
	}
	return nil, ErrUserNotFound
}

func (d *memoryDirectory) FindByLogin(_ context.Context, login string) (*idm.User, error) {
	if user, ok := d.byLogin[login]; ok {
		return proto.Clone(user).(*idm.User), nil
	}
	return nil, ErrUserNotFound
}

func (d *memoryDirectory) Upsert(_ context.Context, user *idm.User) (*idm.User, error) {
	d.store(user)
	return proto.Clone(user).(*idm.User), nil
}

func (d *memoryDirectory) store(user *idm.User) {
	copy := proto.Clone(user).(*idm.User)
	if old, ok := d.byUUID[copy.Uuid]; ok && old.Login != copy.Login {
		delete(d.byLogin, old.Login)
	}
	d.byUUID[copy.Uuid] = copy
	d.byLogin[copy.Login] = copy
}

func TestUserSynchronizerCreatesAndUpdatesStableUser(t *testing.T) {
	t.Parallel()

	directory := newMemoryDirectory()
	syncer := NewUserSynchronizer(directory)
	identity := ExternalIdentity{
		Issuer:      "https://id.example.com/tenant-a",
		Subject:     "user-42",
		Login:       "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}
	identity.UUID, _ = SubjectUUID(identity.Issuer, identity.Subject)

	created, err := syncer.Sync(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if created.Uuid != identity.UUID || created.Login != "alice" {
		t.Fatalf("created user = %#v", created)
	}
	if created.Attributes[AttributeOIDCIssuer] != identity.Issuer || created.Attributes[AttributeOIDCSubject] != identity.Subject {
		t.Fatalf("created user missing identity binding: %#v", created.Attributes)
	}

	identity.Login = "alice.renamed"
	identity.Email = "renamed@example.com"
	updated, err := syncer.Sync(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Uuid != created.Uuid || updated.Login != "alice.renamed" || updated.Attributes["email"] != identity.Email {
		t.Fatalf("updated user = %#v", updated)
	}
	if len(directory.byUUID) != 1 {
		t.Fatalf("synchronizer created %d users, want 1", len(directory.byUUID))
	}
}

func TestUserSynchronizerRejectsLoginCollision(t *testing.T) {
	t.Parallel()

	directory := newMemoryDirectory(&idm.User{Uuid: "local-user", Login: "alice"})
	syncer := NewUserSynchronizer(directory)
	identity := ExternalIdentity{Issuer: "https://id.example.com", Subject: "user-42", Login: "alice"}
	identity.UUID, _ = SubjectUUID(identity.Issuer, identity.Subject)

	_, err := syncer.Sync(context.Background(), identity)
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("Sync() error = %v, want ErrIdentityConflict", err)
	}
}

func TestUserSynchronizerRejectsChangedBinding(t *testing.T) {
	t.Parallel()

	identity := ExternalIdentity{Issuer: "https://id.example.com", Subject: "user-42", Login: "alice"}
	identity.UUID, _ = SubjectUUID(identity.Issuer, identity.Subject)
	directory := newMemoryDirectory(&idm.User{
		Uuid:  identity.UUID,
		Login: "alice",
		Attributes: map[string]string{
			AttributeOIDCIssuer:  "https://other.example.com",
			AttributeOIDCSubject: "other-user",
		},
	})

	_, err := NewUserSynchronizer(directory).Sync(context.Background(), identity)
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("Sync() error = %v, want ErrIdentityConflict", err)
	}
}

// An absent persisted profile is treated as standard by JWT creation, but a
// later REST user/preferences save defaults it to shared. Persist it at birth.
func TestNewOIDCUserPersistsStandardProfileAcrossLogin(t *testing.T) {
	directory := newMemoryDirectory()
	syncer := NewUserSynchronizer(directory)
	identity := ExternalIdentity{Issuer: "https://id.example.com", Subject: "new-member", Login: "member"}
	for i := 0; i < 2; i++ {
		user, err := syncer.Sync(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		if user.Attributes[idm.UserAttrProfile] != "standard" {
			t.Fatalf("login %d: persisted profile = %q, want standard", i, user.Attributes[idm.UserAttrProfile])
		}
	}
	if len(directory.byUUID) != 1 {
		t.Fatal("repeat login duplicated user")
	}
}

func TestOIDCLoginPreservesExistingProfile(t *testing.T) {
	for _, profile := range []string{"standard", "shared", "admin", "anon", "custom"} {
		t.Run(profile, func(t *testing.T) {
			identity := ExternalIdentity{Issuer: "https://id.example.com", Subject: "existing-member", Login: "member"}
			id, _ := SubjectUUID(identity.Issuer, identity.Subject)
			attrs := map[string]string{"locks": "[\"disabled\"]"}
			if profile != "" {
				attrs[idm.UserAttrProfile] = profile
			}
			directory := newMemoryDirectory(&idm.User{Uuid: id, Login: identity.Login, Attributes: attrs})
			user, err := NewUserSynchronizer(directory).Sync(context.Background(), identity)
			if err != nil {
				t.Fatal(err)
			}
			if user.Attributes[idm.UserAttrProfile] != profile || user.Attributes["locks"] != attrs["locks"] {
				t.Fatal("login changed existing profile or account restriction")
			}
		})
	}
}

func TestOIDCLoginPersistsImplicitStandardProfile(t *testing.T) {
	for _, attrs := range []map[string]string{{}, {idm.UserAttrProfile: ""}} {
		identity := ExternalIdentity{Issuer: "https://id.example.com", Subject: "existing-member", Login: "member"}
		id, _ := SubjectUUID(identity.Issuer, identity.Subject)
		directory := newMemoryDirectory(&idm.User{Uuid: id, Login: identity.Login, Attributes: attrs})
		user, err := NewUserSynchronizer(directory).Sync(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		if user.Attributes[idm.UserAttrProfile] != "standard" {
			t.Fatal("implicit standard profile not persisted")
		}
	}
}
