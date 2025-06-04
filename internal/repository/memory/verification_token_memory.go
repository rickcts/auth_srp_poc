package memory

import (
	"context"
	"sync"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

type VerificationTokenEntry struct {
	AuthID string
	Expiry time.Time
}

// MemoryVerificationTokenRepository implements VerificationTokenRepository in memory.
// NOT FOR PRODUCTION use.
type MemoryVerificationTokenRepository struct {
	tokens map[string]VerificationTokenEntry
	mutex  sync.RWMutex
}

// NewMemoryVerificationTokenRepository creates a new in-memory verification token repository.
func NewMemoryVerificationTokenRepository() repository.VerificationTokenRepository {
	return &MemoryVerificationTokenRepository{
		tokens: make(map[string]VerificationTokenEntry),
	}
}

// StorePasswordResetToken saves a new password reset token.
func (r *MemoryVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiry time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.tokens[token] = VerificationTokenEntry{
		AuthID: authID,
		Expiry: expiry,
	}
	return nil
}

// ValidateAndConsumePasswordResetToken checks if a password reset token is valid and consumes it.
func (r *MemoryVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
	r.mutex.Lock() // Lock for read and potential delete
	defer r.mutex.Unlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		// Token expired, clean it up
		delete(r.tokens, token)
		return "", repository.ErrVerificationTokenNotFound
	}

	// Token is valid, consume it (delete) and return authID
	delete(r.tokens, token)
	return entry.AuthID, nil
}

// GetAuthIDForValidPasswordResetToken checks if a password reset token is valid (exists, not expired)
// without consuming it.
func (r *MemoryVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, token string) (string, error) {
	r.mutex.RLock() // Read lock only
	defer r.mutex.RUnlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now().UTC()
	for token, entry := range r.tokens {
		if now.After(entry.Expiry) {
			delete(r.tokens, token)
		}
	}
	if time.Now().UTC().After(entry.Expiry) {
		// Token expired, return not found.
		// Note: This method doesn't clean up expired tokens; cleanup happens on consumption.
		return "", repository.ErrVerificationTokenNotFound
	}

	// Token is valid and not expired
	return entry.AuthID, nil
}

// --- Activation Token Methods ---

// StoreActivationToken saves a new activation token.
func (r *MemoryVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.tokens[token] = VerificationTokenEntry{ // Assuming same entry structure for simplicity
		AuthID: authID,
		Expiry: expiryTime,
	}
	return nil
}

// ValidateAndConsumeActivationToken checks if an activation token is valid and consumes it.
func (r *MemoryVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, token string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		delete(r.tokens, token) // Clean up expired token
		return "", repository.ErrVerificationTokenNotFound
	}

	delete(r.tokens, token) // Consume valid token
	return entry.AuthID, nil
}

// GetAuthIDForValidActivationToken checks if an activation token is valid without consuming it.
func (r *MemoryVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, token string) (string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		// Don't delete here as it's a read-only check
		return "", repository.ErrVerificationTokenNotFound
	}

	return entry.AuthID, nil
}

// Helper for tests or admin purposes, not part of the interface
// Kept for potential internal use or testing, renamed for clarity.
func (r *MemoryVerificationTokenRepository) GetTokenEntry(token string) (VerificationTokenEntry, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	entry, exists := r.tokens[token]
	return entry, exists
}
