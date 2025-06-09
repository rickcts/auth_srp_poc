package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/redis/go-redis/v9"
)

// Token types, used for namespacing and in key construction.
const (
	passwordResetTokenType = "pwreset"
	activationTokenType    = "activate"
)

// RedisVerificationTokenRepository implements VerificationTokenRepository using Redis.
type RedisVerificationTokenRepository struct {
	client *redis.Client
}

// NewRedisVerificationTokenRepository creates a new Redis-backed verification token repository.
func NewRedisVerificationTokenRepository(client *redis.Client) repository.VerificationTokenRepository {
	return &RedisVerificationTokenRepository{
		client: client,
	}
}

// Key for storing the token value itself, keyed by authID and type.
// Format: token:<authID>:<type>
// Value: <token_value>
func makeTokenStorageKey(authID, tokenType string) string {
	return fmt.Sprintf("token:%s:%s", authID, tokenType)
}

// storeToken stores the token_value at a key derived from authID and type.
// This assumes one token of a given type per authID.
func (r *RedisVerificationTokenRepository) storeToken(ctx context.Context, authID, tokenType, tokenValue string, expiryTime time.Time) error {
	key := makeTokenStorageKey(authID, tokenType)
	duration := time.Until(expiryTime)

	if duration <= 0 {
		return fmt.Errorf("expiry time must be in the future")
	}

	// If a previous token for this authID and type existed, storing a new one overwrites it.
	err := r.client.Set(ctx, key, tokenValue, duration).Err()
	if err != nil {
		return fmt.Errorf("failed to store token value in redis (key: %s): %w", key, err)
	}
	return nil
}

// validateAndConsumeToken now takes authIDFromRequest and tokenValueFromRequest.
// It checks if the token stored for authIDFromRequest matches tokenValueFromRequest and consumes it.
func (r *RedisVerificationTokenRepository) validateAndConsumeToken(ctx context.Context, authIDFromRequest, tokenType, tokenValueFromRequest string) (string, error) {
	key := makeTokenStorageKey(authIDFromRequest, tokenType)

	// Atomically GET, COMPARE, and DEL using a Lua script.
	// KEYS[1] = key (e.g., token:user@example.com:pwreset)
	// ARGV[1] = tokenValueFromRequest
	// Returns 1 if successful, 0 if not found, -1 if mismatch.
	script := `
		local stored_token_value = redis.call('GET', KEYS[1])
		if stored_token_value == false then
			return 0 -- Not found
		end
		if stored_token_value ~= ARGV[1] then
			return -1 -- Mismatch
		end
		redis.call('DEL', KEYS[1])
		return 1 -- Success
	`
	result, err := r.client.Eval(ctx, script, []string{key}, tokenValueFromRequest).Int()
	if err != nil {
		// This could be a Redis error (e.g., connection issue) or script error
		return "", fmt.Errorf("lua script execution failed for token consumption (key: %s): %w", key, err)
	}

	switch result {
	case 1: // Success
		return authIDFromRequest, nil
	case 0: // Not found (or expired and already gone)
		return "", repository.ErrVerificationTokenNotFound
	case -1: // Mismatch
		return "", repository.ErrVerificationTokenNotFound // Treat mismatch as not found for security
	default: // Should not happen
		return "", fmt.Errorf("unexpected lua script result for token consumption (key: %s): %d", key, result)
	}
}

// getAuthIDForValidToken now takes authIDFromRequest and tokenValueFromRequest.
// It checks if the token stored for authIDFromRequest matches tokenValueFromRequest.
func (r *RedisVerificationTokenRepository) getAuthIDForValidToken(ctx context.Context, authIDFromRequest, tokenType, tokenValueFromRequest string) (string, error) {
	key := makeTokenStorageKey(authIDFromRequest, tokenType)
	storedTokenValue, err := r.client.Get(ctx, key).Result()

	if err == redis.Nil {
		return "", repository.ErrVerificationTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to retrieve token from redis (key: %s): %w", key, err)
	}

	if storedTokenValue != tokenValueFromRequest {
		return "", repository.ErrVerificationTokenNotFound // Or a specific mismatch error
	}

	return authIDFromRequest, nil // Token is valid for this authID
}

func (r *RedisVerificationTokenRepository) deleteTokensForAuthID(ctx context.Context, authID, tokenType string) error {
	key := makeTokenStorageKey(authID, tokenType)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete token for authID %s, type %s (key: %s): %w", authID, tokenType, key, err)
	}
	return nil
}

// --- Password Reset Token Methods ---

func (r *RedisVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiry time.Time) error {
	return r.storeToken(ctx, authID, passwordResetTokenType, token, expiry)
}

func (r *RedisVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.validateAndConsumeToken(ctx, authIDFromRequest, passwordResetTokenType, tokenFromRequest)
}

func (r *RedisVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.getAuthIDForValidToken(ctx, authIDFromRequest, passwordResetTokenType, tokenFromRequest)
}

func (r *RedisVerificationTokenRepository) DeletePasswordResetTokensForAuthID(ctx context.Context, authID string) error {
	return r.deleteTokensForAuthID(ctx, authID, passwordResetTokenType)
}

// --- Activation Token Methods ---

func (r *RedisVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	return r.storeToken(ctx, authID, activationTokenType, token, expiryTime)
}

func (r *RedisVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.validateAndConsumeToken(ctx, authIDFromRequest, activationTokenType, tokenFromRequest)
}

func (r *RedisVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	return r.getAuthIDForValidToken(ctx, authIDFromRequest, activationTokenType, tokenFromRequest)
}

func (r *RedisVerificationTokenRepository) DeleteActivationTokensForAuthID(ctx context.Context, authID string) error {
	return r.deleteTokensForAuthID(ctx, authID, activationTokenType)
}
