package ent_repo

import (
	"context"
	"fmt"

	"github.com/goccy/go-json"

	"github.com/rickcts/srp/ent"
	"github.com/rickcts/srp/ent/userauth"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
)

// EntUserRepository implements UserRepository to be stored using Ent
type EntUserRepository struct {
	users  map[string]*models.SRPUser
	client *ent.Client
}

func NewEntUserRepository(client *ent.Client) repository.UserRepository {
	return &EntUserRepository{
		users:  make(map[string]*models.SRPUser),
		client: client,
	}
}

func (r *EntUserRepository) CreateUserCreds(ctx context.Context, username, saltHex, verifierHex string) error {
	authExtras := map[string]string{
		"salt":     saltHex,
		"verifier": verifierHex,
	}
	authExtrasJSON, _ := json.Marshal(authExtras)

	user, err := r.client.User.
		Create().
		SetName(username).
		SetState("registered").
		Save(ctx)
	if err != nil {
		return repository.ErrUserExists
	}

	_, err = r.client.UserAuth.
		Create().
		SetAuthProvider("srp").
		SetAuthID(username).
		SetAuthExtras(string(authExtrasJSON)).
		SetUserID(user.ID).
		Save(ctx)

	if err != nil && ent.IsConstraintError(err) {
		return repository.ErrUserExists
	}
	if err != nil {
		// Maybe log the specific error here for debugging
		// log.Printf("Error during Save: %v", err)
		return fmt.Errorf("database save failed: %w", err) // Make sure you return the error
	}
	fmt.Printf("User registered: %s\n", username) // Debug log
	return nil
}

func (r *EntUserRepository) GetUserCredsByUsername(ctx context.Context, username string) (string, string, error) {
	user, err := r.client.UserAuth.
		Query().
		Where(userauth.AuthProvider("srp"), userauth.AuthID(username)).
		Only(ctx)

	if err != nil && ent.IsNotFound(err) {
		return "", "", repository.ErrUserNotFound
	}

	userAuthExtras := map[string]string{}
	json.Unmarshal([]byte(user.AuthExtras), &userAuthExtras)
	saltHex := userAuthExtras["salt"]
	verifierHex := userAuthExtras["verifier"]

	return saltHex, verifierHex, nil
}
