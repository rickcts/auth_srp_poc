package memory

import (
	"context"
	"sync"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

type passwordResetTokenEntry struct {
	AuthID string
	Expiry time.Time
}

// MemoryPasswordResetTokenRepository implements PasswordResetTokenRepository in memory.
// NOT FOR PRODUCTION use.
type MemoryPasswordResetTokenRepository struct {
	tokens map[string]passwordResetTokenEntry
	mutex  sync.RWMutex
}

// NewMemoryPasswordResetTokenRepository creates a new in-memory password reset token repository.
func NewMemoryPasswordResetTokenRepository() repository.PasswordResetTokenRepository {
	return &MemoryPasswordResetTokenRepository{
		tokens: make(map[string]passwordResetTokenEntry),
	}
}

// StoreResetToken saves a new reset token.
func (r *MemoryPasswordResetTokenRepository) StoreResetToken(ctx context.Context, authID string, token string, expiry time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.tokens[token] = passwordResetTokenEntry{
		AuthID: authID,
		Expiry: expiry,
	}
	return nil
}

// ValidateAndConsumeResetToken checks if a token is valid and consumes it.
func (r *MemoryPasswordResetTokenRepository) ValidateAndConsumeResetToken(ctx context.Context, token string) (string, error) {
	r.mutex.Lock() // Lock for read and potential delete
	defer r.mutex.Unlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrPasswordResetTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		// Token expired, clean it up
		delete(r.tokens, token)
		return "", repository.ErrPasswordResetTokenNotFound
	}

	// Token is valid, consume it (delete) and return authID
	delete(r.tokens, token)
	return entry.AuthID, nil
}

// Helper for tests or admin purposes, not part of the interface
func (r *MemoryPasswordResetTokenRepository) GetTokenEntry(token string) (passwordResetTokenEntry, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	entry, exists := r.tokens[token]
	return entry, exists
}

// CleanupExpiredTokens can be called periodically if desired, though ValidateAndConsumeResetToken also cleans up.
func (r *MemoryPasswordResetTokenRepository) CleanupExpiredTokens() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now().UTC()
	for token, entry := range r.tokens {
		if now.After(entry.Expiry) {
			delete(r.tokens, token)
		}
	}
} // GetAuthIDForValidToken checks if a token is valid (exists, not expired)
// without consuming it.
func (r *MemoryPasswordResetTokenRepository) GetAuthIDForValidToken(ctx context.Context, token string) (string, error) {
	r.mutex.RLock() // Read lock only
	defer r.mutex.RUnlock()

	entry, exists := r.tokens[token]
	if !exists {
		return "", repository.ErrPasswordResetTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		// Token expired, return not found.
		// Note: This method doesn't clean up expired tokens; cleanup happens on consumption.
		return "", repository.ErrPasswordResetTokenNotFound
	}

	// Token is valid and not expired
	return entry.AuthID, nil
}
