package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/redis/go-redis/v9"
)

// RedisSessionRepository implements SessionRepository using Redis.
type RedisSessionRepository struct {
	client *redis.Client
}

// Helper to construct session key
func makeSessionKey(SessionID string) string {
	return fmt.Sprintf("session:%s", SessionID)
}

// Helper to construct user index key
func makeUserSessionsKey(userID int64) string {
	return fmt.Sprintf("user_sessions:%v", userID)
}

func NewRedisSessionRepository(client *redis.Client) repository.SessionRepository {
	return &RedisSessionRepository{
		client: client,
	}
}

// StoreSession saves the session data and adds it to the user's session index.
func (r *RedisSessionRepository) StoreSession(ctx context.Context, session *models.Session) error {
	if session == nil || session.SessionID == "" || session.UserID <= 0 {
		return errors.New("invalID session data: SessionID and userID must be set")
	}

	jsonData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := max(time.Until(session.Expiry), 0)
	if ttl <= 0 {
		return r.DeleteSession(ctx, session.SessionID)
	}

	sessionKey := makeSessionKey(session.SessionID)
	userKey := makeUserSessionsKey(session.UserID)

	pipe := r.client.TxPipeline()

	// Store the session data (String/JSON)
	pipe.Set(ctx, sessionKey, jsonData, ttl)

	// Add the session ID to the user's Set
	pipe.SAdd(ctx, userKey, session.SessionID)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute session store pipeline: %w", err)
	}

	return nil
}

// GetSession retrieves a session by its ID from Redis.
// It returns ErrSessionNotFound if the session doesn't exist or is expired (handled by Redis TTL).
// It also performs an additional check on the deserialized session's IsExpired() method
func (r *RedisSessionRepository) GetSession(ctx context.Context, SessionID string) (*models.Session, error) {
	sessionKey := makeSessionKey(SessionID) // Use the new key pattern

	jsonData, err := r.client.Get(ctx, sessionKey).Bytes()
	if err == redis.Nil {
		return nil, repository.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis GET failed: %w", err)
	}

	var session models.Session
	if err := json.Unmarshal(jsonData, &session); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	if session.IsExpired() {
		pipe := r.client.Pipeline()
		pipe.Del(ctx, sessionKey)
		if session.UserID <= 0 { // Only try to remove from set if userID is present
			pipe.SRem(ctx, makeUserSessionsKey(session.UserID), SessionID)
		}
		_, _ = pipe.Exec(ctx)
		return nil, repository.ErrSessionNotFound
	}

	return &session, nil
}

// DeleteSession removes a session and its index entry.
func (r *RedisSessionRepository) DeleteSession(ctx context.Context, SessionID string) error {
	sessionKey := makeSessionKey(SessionID)

	// Get the session data to find the userID.
	jsonData, err := r.client.Get(ctx, sessionKey).Bytes()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get session before delete: %w", err)
	}

	var session models.Session
	if err := json.Unmarshal(jsonData, &session); err != nil {
		r.client.Del(ctx, sessionKey)
		return fmt.Errorf("failed to unmarshal session before delete (key deleted): %w", err)
	}

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, sessionKey)
	if session.UserID <= 0 {
		userKey := makeUserSessionsKey(session.UserID)
		pipe.SRem(ctx, userKey, SessionID)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute session delete pipeline: %w", err)
	}

	return nil
}

// ExtendSession updates the expiry and stores the session with the new TTL.
func (r *RedisSessionRepository) ExtendSession(ctx context.Context, SessionID string, newExpiry time.Time) error {
	sessionKey := makeSessionKey(SessionID)

	jsonData, err := r.client.Get(ctx, sessionKey).Bytes()
	if err == redis.Nil {
		return repository.ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("redis GET failed during extend: %w", err)
	}

	var currentSession models.Session
	if err := json.Unmarshal(jsonData, &currentSession); err != nil {
		return fmt.Errorf("json unmarshal failed during extend: %w", err)
	}

	if currentSession.IsExpired() {
		r.DeleteSession(ctx, SessionID)
		return repository.ErrSessionNotFound
	}

	currentSession.Expiry = newExpiry
	updatedJsonData, err := json.Marshal(currentSession)
	if err != nil {
		return fmt.Errorf("json marshal failed during extend: %w", err)
	}

	ttl := max(time.Until(newExpiry), 0)

	err = r.client.Set(ctx, sessionKey, updatedJsonData, ttl).Err()
	if err != nil {
		return fmt.Errorf("redis SET failed during extend: %w", err)
	}

	return nil
}

// DeleteUserSessions deletes all sessions for a user, optionally excluding some.
// It returns the count of sessions that were actually deleted and an error if one occurred.
func (r *RedisSessionRepository) DeleteUserSessions(ctx context.Context, userID int64, excludeTokenIDs ...string) (int64, error) {
	userKey := makeUserSessionsKey(userID)

	// Get all session IDs for the user.
	SessionIDs, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get user sessions with SMEMBERS: %w", err)
	}

	if len(SessionIDs) == 0 {
		return 0, nil
	}

	excludeMap := make(map[string]struct{}, len(excludeTokenIDs))
	for _, ID := range excludeTokenIDs {
		excludeMap[ID] = struct{}{}
	}

	// Filter sessions to find those to delete.
	var sessionKeysToDelete []string
	var SessionIDsToRemoveFromSet []string

	for _, ID := range SessionIDs {
		if _, shouldExclude := excludeMap[ID]; !shouldExclude {
			sessionKeysToDelete = append(sessionKeysToDelete, makeSessionKey(ID))
			SessionIDsToRemoveFromSet = append(SessionIDsToRemoveFromSet, ID)
		}
	}

	if len(sessionKeysToDelete) == 0 {
		return 0, nil
	}

	pipe := r.client.TxPipeline()
	delCmd := pipe.Del(ctx, sessionKeysToDelete...)

	// Remove the relevant session IDs from the user's set.
	sremArgs := make([]interface{}, len(SessionIDsToRemoveFromSet))
	for i, v := range SessionIDsToRemoveFromSet {
		sremArgs[i] = v
	}
	pipe.SRem(ctx, userKey, sremArgs...)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to execute user sessions delete pipeline: %w", err)
	}

	deletedCount := delCmd.Val()

	return deletedCount, nil
}
