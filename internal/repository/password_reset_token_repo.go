package repository

import (
	"context"
	"fmt"
	"time"
)

// ErrPasswordResetTokenNotFound is returned when a token is not found, is expired, or has been used.
var ErrPasswordResetTokenNotFound = fmt.Errorf("password reset token not found or invalid")

// PasswordResetTokenRepository defines operations for managing password reset tokens.
type PasswordResetTokenRepository interface {
	// StoreResetToken saves a new reset token with an associated authID and expiry.
	StoreResetToken(ctx context.Context, authID string, token string, expiry time.Time) error
	// ValidateAndConsumeResetToken checks if a token is valid (exists, not expired)
	// and if so, returns the associated authID and consumes (deletes) the token to prevent reuse.
	// It should return ErrPasswordResetTokenNotFound if the token is invalid or not found.
	ValidateAndConsumeResetToken(ctx context.Context, token string) (authID string, err error)
}
