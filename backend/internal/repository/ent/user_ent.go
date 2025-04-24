package ent_repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rickcts/srp/ent"
	"github.com/rickcts/srp/ent/userauth"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
)

// EntUserRepository implements UserRepository to be stored using Ent
type EntUserRepository struct {
	users  map[string]*models.User
	client *ent.Client
}

func NewEntUserRepository(client *ent.Client) repository.UserRepository {
	return &EntUserRepository{
		users: make(map[string]*models.User),
	}
}

func (r *EntUserRepository) CreateUserCreds(ctx context.Context, username, saltHex, verifierHex string) error {
	authExtras := map[string]string{
		"salt":     saltHex,
		"verifier": verifierHex,
	}
	authExtrasJSON, _ := json.Marshal(authExtras)

	_, err := r.client.UserAuth.
		Create().
		SetAuthProvider("srp").
		SetAuthID(username).
		SetAuthExtras(string(authExtrasJSON)).
		Save(ctx)
	if err != nil && ent.IsConstraintError(err) {
		return repository.ErrUserExists
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
