// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"context"
	"errors"
	"fmt"

	"github.com/pydio/cells/v5/common/client/commons/idmc"
	cellerrors "github.com/pydio/cells/v5/common/errors"
	"github.com/pydio/cells/v5/common/permissions"
	"github.com/pydio/cells/v5/common/proto/idm"
)

const (
	AttributeOIDCIssuer  = "oidc:issuer"
	AttributeOIDCSubject = "oidc:subject"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrIdentityConflict = errors.New("OIDC identity conflicts with an existing Cells user")
)

type UserDirectory interface {
	FindByUUID(ctx context.Context, uuid string) (*idm.User, error)
	FindByLogin(ctx context.Context, login string) (*idm.User, error)
	Upsert(ctx context.Context, user *idm.User) (*idm.User, error)
}

type UserSyncer interface {
	Sync(ctx context.Context, identity ExternalIdentity) (*idm.User, error)
}

type UserSynchronizer struct {
	directory UserDirectory
}

func NewUserSynchronizer(directory UserDirectory) *UserSynchronizer {
	return &UserSynchronizer{directory: directory}
}

func (s *UserSynchronizer) Sync(ctx context.Context, identity ExternalIdentity) (*idm.User, error) {
	expectedUUID, err := SubjectUUID(identity.Issuer, identity.Subject)
	if err != nil {
		return nil, err
	}
	if identity.UUID != "" && identity.UUID != expectedUUID {
		return nil, fmt.Errorf("%w: supplied UUID does not match issuer and subject", ErrIdentityConflict)
	}
	identity.UUID = expectedUUID

	existing, err := s.directory.FindByUUID(ctx, identity.UUID)
	switch {
	case err == nil:
		if err := verifyStoredBinding(existing, identity); err != nil {
			return nil, err
		}
		if existing.Login != identity.Login {
			collision, collisionErr := s.directory.FindByLogin(ctx, identity.Login)
			if collisionErr == nil && collision.Uuid != existing.Uuid {
				return nil, fmt.Errorf("%w: login %q belongs to another user", ErrIdentityConflict, identity.Login)
			}
			if collisionErr != nil && !errors.Is(collisionErr, ErrUserNotFound) {
				return nil, collisionErr
			}
		}
		return s.directory.Upsert(ctx, mergeIdentity(existing, identity))
	case !errors.Is(err, ErrUserNotFound):
		return nil, err
	}

	if collision, collisionErr := s.directory.FindByLogin(ctx, identity.Login); collisionErr == nil {
		return nil, fmt.Errorf("%w: login %q belongs to user %q", ErrIdentityConflict, identity.Login, collision.Uuid)
	} else if !errors.Is(collisionErr, ErrUserNotFound) {
		return nil, collisionErr
	}

	return s.directory.Upsert(ctx, mergeIdentity(&idm.User{Uuid: identity.UUID}, identity))
}

func verifyStoredBinding(user *idm.User, identity ExternalIdentity) error {
	if user.Attributes == nil {
		return nil
	}
	if issuer := user.Attributes[AttributeOIDCIssuer]; issuer != "" && issuer != identity.Issuer {
		return fmt.Errorf("%w: stored issuer differs", ErrIdentityConflict)
	}
	if subject := user.Attributes[AttributeOIDCSubject]; subject != "" && subject != identity.Subject {
		return fmt.Errorf("%w: stored subject differs", ErrIdentityConflict)
	}
	return nil
}

func mergeIdentity(user *idm.User, identity ExternalIdentity) *idm.User {
	out := &idm.User{
		Uuid:       identity.UUID,
		Login:      identity.Login,
		GroupPath:  user.GetGroupPath(),
		Roles:      user.GetRoles(),
		Policies:   user.GetPolicies(),
		Attributes: make(map[string]string, len(user.GetAttributes())+4),
	}
	for key, value := range user.GetAttributes() {
		out.Attributes[key] = value
	}
	out.Attributes[AttributeOIDCIssuer] = identity.Issuer
	out.Attributes[AttributeOIDCSubject] = identity.Subject
	if identity.Email != "" {
		out.Attributes["email"] = identity.Email
	}
	if identity.DisplayName != "" {
		out.Attributes["name"] = identity.DisplayName
	}
	return out
}

type CellsDirectory struct{}

func (CellsDirectory) FindByUUID(ctx context.Context, uuid string) (*idm.User, error) {
	user, err := permissions.SearchUniqueUser(ctx, "", uuid)
	return normalizeDirectoryError(user, err)
}

func (CellsDirectory) FindByLogin(ctx context.Context, login string) (*idm.User, error) {
	user, err := permissions.SearchUniqueUser(ctx, login, "")
	return normalizeDirectoryError(user, err)
}

func (CellsDirectory) Upsert(ctx context.Context, user *idm.User) (*idm.User, error) {
	response, err := idmc.UserServiceClient(ctx).CreateUser(ctx, &idm.CreateUserRequest{User: user})
	if err != nil {
		return nil, err
	}
	return response.GetUser(), nil
}

func normalizeDirectoryError(user *idm.User, err error) (*idm.User, error) {
	if cellerrors.Is(err, cellerrors.UserNotFound) {
		return nil, ErrUserNotFound
	}
	return user, err
}
