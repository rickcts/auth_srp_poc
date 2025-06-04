package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/redis/go-redis/v9"
)

const (
	passwordResetTokenPrefix = "reset:"
	activationTokenPrefix    = "activation:"
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

func (r *RedisVerificationTokenRepository) storeToken(ctx context.Context, prefix, authID, token string, expiryTime time.Time) error {
	key := prefix + token
	duration := time.Until(expiryTime)

	if duration <= 0 {
		return fmt.Errorf("expiry time must be in the future")
	}

	err := r.client.Set(ctx, key, authID, duration).Err()
	if err != nil {
		return fmt.Errorf("failed to store token in redis (prefix: %s): %w", prefix, err)
	}
	return nil
}

func (r *RedisVerificationTokenRepository) validateAndConsumeToken(ctx context.Context, prefix, token string) (string, error) {
	key := prefix + token

	pipe := r.client.TxPipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return "", fmt.Errorf("failed to execute validate and consume token transaction (prefix: %s): %w", prefix, err)
	}

	authID, getErr := getCmd.Result()
	if getErr == redis.Nil {
		return "", repository.ErrVerificationTokenNotFound
	}
	if getErr != nil {
		return "", fmt.Errorf("failed to retrieve token from redis (prefix: %s): %w", prefix, getErr)
	}
	return authID, nil
}

func (r *RedisVerificationTokenRepository) getAuthIDForValidToken(ctx context.Context, prefix, token string) (string, error) {
	key := prefix + token
	authID, err := r.client.Get(ctx, key).Result()

	if err == redis.Nil {
		return "", repository.ErrVerificationTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to retrieve token from redis (prefix: %s): %w", prefix, err)
	}
	return authID, nil
}

// --- Password Reset Token Methods ---

func (r *RedisVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiry time.Time) error {
	return r.storeToken(ctx, passwordResetTokenPrefix, authID, token, expiry)
}

func (r *RedisVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
	return r.validateAndConsumeToken(ctx, passwordResetTokenPrefix, token)
}

func (r *RedisVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, token string) (string, error) {
	return r.getAuthIDForValidToken(ctx, passwordResetTokenPrefix, token)
}

// --- Activation Token Methods ---

func (r *RedisVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	return r.storeToken(ctx, activationTokenPrefix, authID, token, expiryTime)
}

func (r *RedisVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, token string) (string, error) {
	return r.validateAndConsumeToken(ctx, activationTokenPrefix, token)
}

func (r *RedisVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, token string) (string, error) {
	return r.getAuthIDForValidToken(ctx, activationTokenPrefix, token)
}
