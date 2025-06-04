package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/redis/go-redis/v9"
)

const (
	passwordResetTokenPrefix = "pwdreset:"
)

// RedisPasswordResetTokenRepository implements PasswordResetTokenRepository using Redis.
type RedisPasswordResetTokenRepository struct {
	client *redis.Client
}

// NewRedisPasswordResetTokenRepository creates a new Redis-backed password reset token repository.
func NewRedisPasswordResetTokenRepository(client *redis.Client) repository.PasswordResetTokenRepository {
	return &RedisPasswordResetTokenRepository{
		client: client,
	}
}

func (r *RedisPasswordResetTokenRepository) makeKey(token string) string {
	return passwordResetTokenPrefix + token
}

// StoreResetToken saves a new reset token (6-digit code) with an associated authID and expiry.
// The token itself is part of the key for simplicity with 6-digit codes,
// and the value is the authID.
func (r *RedisPasswordResetTokenRepository) StoreResetToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	key := r.makeKey(token)
	duration := time.Until(expiryTime)

	if duration <= 0 {
		return fmt.Errorf("expiry time must be in the future")
	}

	err := r.client.Set(ctx, key, authID, duration).Err()
	if err != nil {
		return fmt.Errorf("failed to store password reset token in redis: %w", err)
	}
	return nil
}

// ValidateAndConsumeResetToken checks if a token (6-digit code) is valid and consumes it.
func (r *RedisPasswordResetTokenRepository) ValidateAndConsumeResetToken(ctx context.Context, token string) (string, error) {
	key := r.makeKey(token)

	// Use a transaction to get and delete atomically.
	pipe := r.client.TxPipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to validate and consume password reset token: %w", err)
	}

	authID, getErr := getCmd.Result()

	if getErr == redis.Nil { // Token not found (or already consumed)
		return "", repository.ErrPasswordResetTokenNotFound
	}
	if getErr != nil { // Other Redis error during Get
		return "", fmt.Errorf("failed to retrieve password reset token from redis: %w", getErr)
	}

	return authID, nil
}

// GetAuthIDForValidToken checks if a token (6-digit code) is valid (exists and not expired)
// without consuming it.
func (r *RedisPasswordResetTokenRepository) GetAuthIDForValidToken(ctx context.Context, token string) (string, error) {
	key := r.makeKey(token)

	authID, err := r.client.Get(ctx, key).Result()

	if err == redis.Nil { // Token not found or expired
		return "", repository.ErrPasswordResetTokenNotFound
	}
	if err != nil { // Other Redis error
		return "", fmt.Errorf("failed to retrieve password reset token from redis: %w", err)
	}

	// If we got here, the token exists and was not expired at the time of the GET call.
	return authID, nil
}
