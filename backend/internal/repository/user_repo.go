package repository

import (
	"fmt"
)

// UserRepository defines operations for storing/retrieving user credentials
type UserRepository interface {
	// CreateUserCreds stores the SRP credentials (hex-encoded salt 's' and verifier 'v')
	// for a new user identified by username.
	// It should return ErrUserExists if the username is already taken,
	// or another error if the storage operation fails.
	CreateUserCreds(username, saltHex, verifierHex string) error

	// GetUserCredsByUsername retrieves the hex-encoded salt and verifier for a given username.
	// It should return ErrUserNotFound if the user does not exist.
	GetUserCredsByUsername(username string) (saltHex, verifierHex string, err error)
}

// Common errors
var ErrUserNotFound = fmt.Errorf("user not found")
var ErrUserExists = fmt.Errorf("user already exists")
