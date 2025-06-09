package memory

import (
	"context"
	"sync"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

// VerificationTokenEntry stores the token value and its expiry.
type VerificationTokenEntry struct {
	TokenValue string
	Expiry     time.Time
}

// MemoryVerificationTokenRepository implements VerificationTokenRepository in memory.
// NOT FOR PRODUCTION use.
type MemoryVerificationTokenRepository struct {
	// tokens map[string]VerificationTokenEntry // Old: token_value -> {authID, expiry}
	// New: authID_type -> {token_value, expiry}
	// Example key: "user@example.com:pwreset"
	// Example key: "user@example.com:activate"
	tokens map[string]VerificationTokenEntry
	mutex  sync.RWMutex
}

// NewMemoryVerificationTokenRepository creates a new in-memory verification token repository.
func NewMemoryVerificationTokenRepository() repository.VerificationTokenRepository {
	return &MemoryVerificationTokenRepository{
		tokens: make(map[string]VerificationTokenEntry),
	}
}

func makeMemoryKey(authID, tokenType string) string {
	return authID + ":" + tokenType
}

func (r *MemoryVerificationTokenRepository) storeToken(ctx context.Context, authID, tokenType, tokenValue string, expiryTime time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if time.Until(expiryTime) <= 0 {
		return repository.ErrVerificationTokenNotFound // Or specific error
	}
	key := makeMemoryKey(authID, tokenType)
	r.tokens[key] = VerificationTokenEntry{
		TokenValue: tokenValue,
		Expiry:     expiryTime,
	}
	return nil
}

func (r *MemoryVerificationTokenRepository) validateAndConsumeToken(ctx context.Context, authIDFromRequest, tokenType, tokenValueFromRequest string) (string, error) {
	r.mutex.Lock() // Lock for read and potential delete
	defer r.mutex.Unlock()

	key := makeMemoryKey(authIDFromRequest, tokenType)
	entry, exists := r.tokens[key]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	if time.Now().UTC().After(entry.Expiry) {
		// Token expired, clean it up
		delete(r.tokens, key)
		return "", repository.ErrVerificationTokenNotFound
	}

	if entry.TokenValue != tokenValueFromRequest {
		// Token mismatch, do not consume.
		return "", repository.ErrVerificationTokenNotFound
	}

	// Token is valid and matches, consume it (delete) and return authID
	delete(r.tokens, key)
	return authIDFromRequest, nil
}

func (r *MemoryVerificationTokenRepository) getAuthIDForValidToken(ctx context.Context, authIDFromRequest, tokenType, tokenValueFromRequest string) (string, error) {
	r.mutex.RLock() // Read lock only
	defer r.mutex.RUnlock()

	key := makeMemoryKey(authIDFromRequest, tokenType)
	entry, exists := r.tokens[key]
	if !exists {
		return "", repository.ErrVerificationTokenNotFound
	}

	// Perform cleanup of expired tokens (optional, but good for memory repo)
	// This part is tricky with RLock. For simplicity, GetAuthIDForValidToken might not aggressively clean.
	// A separate cleanup goroutine or cleanup on write operations is better for memory repo.
	// For now, just check current token's expiry.
	now := time.Now().UTC()
	if now.After(entry.Expiry) {
		return "", repository.ErrVerificationTokenNotFound
	}

	if entry.TokenValue != tokenValueFromRequest {
		return "", repository.ErrVerificationTokenNotFound
	}

	// Token is valid, not expired, and matches
	return authIDFromRequest, nil
}

func (r *MemoryVerificationTokenRepository) deleteTokensForAuthID(ctx context.Context, authID, tokenType string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	key := makeMemoryKey(authID, tokenType)
	delete(r.tokens, key)
	return nil
}

// --- Activation Token Methods ---

// StoreActivationToken saves a new activation token.
func (r *MemoryVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	return r.storeToken(ctx, authID, "activate", token, expiryTime)
}

// ValidateAndConsumeActivationToken checks if an activation token is valid and consumes it.
func (r *MemoryVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.validateAndConsumeToken(ctx, authIDFromRequest, "activate", tokenFromRequest)
}

// GetAuthIDForValidActivationToken checks if an activation token is valid without consuming it.
func (r *MemoryVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.getAuthIDForValidToken(ctx, authIDFromRequest, "activate", tokenFromRequest)
}

func (r *MemoryVerificationTokenRepository) DeleteActivationTokensForAuthID(ctx context.Context, authID string) error {
	return r.deleteTokensForAuthID(ctx, authID, "activate")
}

// --- Password Reset Token Methods ---

func (r *MemoryVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiry time.Time) error {
	return r.storeToken(ctx, authID, "pwreset", token, expiry)
}

func (r *MemoryVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.validateAndConsumeToken(ctx, authIDFromRequest, "pwreset", tokenFromRequest)
}

func (r *MemoryVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.getAuthIDForValidToken(ctx, authIDFromRequest, "pwreset", tokenFromRequest)
}

func (r *MemoryVerificationTokenRepository) DeletePasswordResetTokensForAuthID(ctx context.Context, authID string) error {
	return r.deleteTokensForAuthID(ctx, authID, "pwreset")
}

// Helper for tests or admin purposes, not part of the interface
// Kept for potential internal use or testing, renamed for clarity.
func (r *MemoryVerificationTokenRepository) GetTokenEntry(authID, tokenType string) (VerificationTokenEntry, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	key := makeMemoryKey(authID, tokenType)
	entry, exists := r.tokens[key]
	return entry, exists
}
