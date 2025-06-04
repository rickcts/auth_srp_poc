package repository

import (
	"context"
	"fmt"
	"time"
)

// ErrVerificationTokenNotFound is returned when a token is not found, is expired, or has been used.
var ErrVerificationTokenNotFound = fmt.Errorf("verification token not found or invalid")

// VerificationTokenRepository defines operations for managing various types of single-use tokens.
type VerificationTokenRepository interface {
	// --- Password Reset Tokens ---
	// StorePasswordResetToken saves a new password reset token.
	StorePasswordResetToken(ctx context.Context, authID string, token string, expiry time.Time) error
	// ValidateAndConsumePasswordResetToken checks if a password reset token is valid
	// and if so, returns the associated authID and consumes (deletes) the token to prevent reuse.
	// It should return ErrVerificationTokenNotFound if the token is invalid or not found.
	ValidateAndConsumePasswordResetToken(ctx context.Context, token string) (authID string, err error)
	// GetAuthIDForValidPasswordResetToken checks if a password reset token is valid without consuming it.
	GetAuthIDForValidPasswordResetToken(ctx context.Context, token string) (authID string, err error)

	// --- Activation Tokens ---
	// StoreActivationToken saves a new activation token.
	StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error
	// ValidateAndConsumeActivationToken checks if an activation token is valid and consumes it.
	ValidateAndConsumeActivationToken(ctx context.Context, token string) (authID string, err error)
	// GetAuthIDForValidActivationToken checks if an activation token is valid without consuming it.
	GetAuthIDForValidActivationToken(ctx context.Context, token string) (authID string, err error)
}
