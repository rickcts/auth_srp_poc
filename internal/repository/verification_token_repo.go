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
	// ValidateAndConsumePasswordResetToken checks if the provided token matches the one stored for the authID,
	// and if so, returns the authID and consumes (deletes) the token.
	// It should return ErrVerificationTokenNotFound if no token is stored, it doesn't match, or is expired.
	ValidateAndConsumePasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (authID string, err error)
	// GetAuthIDForValidPasswordResetToken checks if the provided token matches the one stored for the authID without consuming it.
	GetAuthIDForValidPasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (authID string, err error)
	// DeletePasswordResetTokensForAuthID removes all password reset tokens associated with an authID.
	DeletePasswordResetTokensForAuthID(ctx context.Context, authID string) error

	// --- Activation Tokens ---
	// StoreActivationToken saves a new activation token.
	StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error
	// ValidateAndConsumeActivationToken checks if the provided token matches the one stored for the authID and consumes it.
	ValidateAndConsumeActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (authID string, err error)
	// GetAuthIDForValidActivationToken checks if the provided token matches the one stored for the authID without consuming it.
	GetAuthIDForValidActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (authID string, err error)
	// DeleteActivationTokensForAuthID removes all activation tokens associated with an authID.
	DeleteActivationTokensForAuthID(ctx context.Context, authID string) error
}
