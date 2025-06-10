package repository

import (
	"context"
	"fmt"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
)

// UserRepository defines operations for storing/retrieving user credentials
type UserRepository interface {
	// CreateUser stores the user credentials
	// It should return ErrUserExists if the user ID (email account or oIDc <aud>:<sub>) is already taken,
	// or other errors if the operation fails.
	CreateUser(ctx context.Context, authID, displayName, authProvIDer string, authExtras any) error

	// CheckIfUserExists check if the auth ID exist in the database
	// If should return errors if the operation fails.
	CheckIfUserExists(ctx context.Context, authID string) (bool, error)

	// Set user as active
	ActivateUser(ctx context.Context, authID int64) error

	// GetUser retrieves the information.
	// It should return ErrUserNotFound if the user does not exist.
	GetUserInfoByAuthID(ctx context.Context, authID string) (userInfo *models.UserInfo, err error)

	// UpdateUserSRPAuth updates the salt and verifier for an SRP user.
	// It should return ErrUserNotFound if the user does not exist.
	UpdateUserSRPAuth(ctx context.Context, authID string, newSaltHex string, newVerifierHex string) error

	UpdateUserInfoByAuthID(ctx context.Context, authID string, displayName string) error

	DeleteUser(ctx context.Context, authID string) error

	CreateUserAuthEvent(ctx context.Context, userID int64, host string, errorCode int) error
}

// Common errors
var ErrUserNotFound = fmt.Errorf("user not found")
var ErrUserExists = fmt.Errorf("user already exists")
var ErrUserNotActivated = fmt.Errorf("user has not been activated")
