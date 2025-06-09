package ent_repo

import (
	"context"
	"fmt"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/user"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/userauth"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

// EntUserRepository implements UserRepository to be stored using Ent
type EntUserRepository struct {
	client *ent.Client
}

func NewEntUserRepository(client *ent.Client) repository.UserRepository {
	return &EntUserRepository{
		client: client,
	}
}

func (r *EntUserRepository) CheckIfUserExists(ctx context.Context, AuthID string) (bool, error) {
	isExist, err := r.client.User.
		Query().
		Where(user.HasUserAuthWith(userauth.AuthID(AuthID))).
		Exist(ctx)

	return isExist, err
}

func (r *EntUserRepository) CreateUser(
	ctx context.Context,
	AuthID string,
	displayName string,
	authProvider string,
	authExtras any) error {

	user, err := r.client.User.
		Create().
		SetDisplayName(displayName).
		SetState("inactive").
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	extraJSON, err := json.Marshal(authExtras)
	if err != nil {
		return fmt.Errorf("failed to marshal user extras: %w", err)
	}

	userAuth := r.client.UserAuth.
		Create().
		SetAuthID(AuthID).
		SetAuthProvider(authProvider).
		SetAuthExtras(string(extraJSON)).
		SetUserID(user.ID).
		SaveX(ctx)

	fmt.Printf("User registered: %v\n", userAuth.ID)
	return nil
}

func (r *EntUserRepository) ActivateUser(ctx context.Context, userId int64) error {
	err := r.client.User.
		UpdateOneID(userId).
		SetState("active").
		Exec(ctx)
	if err != nil {
		return repository.ErrUserNotFound
	}

	return nil
}

func (r *EntUserRepository) GetUserInfoByAuthID(ctx context.Context, AuthID string) (userInfo *models.UserInfo, err error) {
	ua, err := r.client.UserAuth.
		Query().
		Where(userauth.AuthIDEQ(AuthID)).
		WithUser().
		Only(ctx)
	if err != nil && ent.IsNotFound(err) {
		return nil, repository.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database query failed for user auth: %w", err)
	}

	user := &models.UserInfo{
		ID:           ua.Edges.User.ID,
		DisplayName:  ua.Edges.User.DisplayName,
		State:        ua.Edges.User.State,
		AuthID:       ua.AuthID,
		AuthProvider: ua.AuthProvider,
		AuthExtras:   map[string]string{},
	}
	err = json.Unmarshal([]byte(ua.AuthExtras), &user.AuthExtras)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user extras: %w", err)
	}
	return user, nil
}

func (r *EntUserRepository) UpdateUserSRPAuth(ctx context.Context, authID string, newSaltHex string, newVerifierHex string) error {
	ua, err := r.client.UserAuth.
		Query().
		Where(userauth.AuthIDEQ(authID)).
		// Ensure it's an SRP user if you have different types of auth_extras
		// Where(userauth.AuthProviderEQ("SRP6")).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return repository.ErrUserNotFound
		}
		return fmt.Errorf("failed to find user auth for update: %w", err)
	}

	authExtras := map[string]string{}
	err = json.Unmarshal([]byte(ua.AuthExtras), &authExtras)
	if err != nil {
		return fmt.Errorf("failed to unmarshal old user extras: %w", err)
	}
	authExtras["salt"] = newSaltHex
	authExtras["verifier"] = newVerifierHex

	extraJSON, err := json.Marshal(authExtras)
	if err != nil {
		return fmt.Errorf("failed to marshal new user extras: %w", err)
	}

	_, err = ua.Update().SetAuthExtras(string(extraJSON)).Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update user auth extras: %w", err)
	}
	return nil
}

func (r *EntUserRepository) UpdateUserInfoByAuthID(ctx context.Context, authID string, displayName string) error {
	_, err := r.client.User.
		Update().
		Where(user.HasUserAuthWith(userauth.AuthIDEQ(authID))).
		SetDisplayName(displayName).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update user info: %w", err)
	}
	return nil
}

func (r *EntUserRepository) DeleteUser(ctx context.Context, authID string) error {
	_, err := r.client.User.
		Delete().
		Where(user.HasUserAuthWith(userauth.AuthIDEQ(authID))).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (r *EntUserRepository) CreateUserAuthEvent(ctx context.Context, host string, errorCode int) error {
	_, err := r.client.UserAuthEvent.
		Create().
		SetHost(host).
		SetErrorCode(errorCode).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to store auth event: %w", err)
	}
	return nil
}
