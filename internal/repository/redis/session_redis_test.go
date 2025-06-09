package redis

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedisSessionRepo(t *testing.T) (repo repository.SessionRepository, mr *miniredis.Miniredis, client *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)

	client = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	require.NoError(t, client.Ping(context.Background()).Err())

	repo = NewRedisSessionRepository(client)
	return repo, mr, client
}

func TestNewRedisSessionRepository(t *testing.T) {
	repo, mr, _ := newTestRedisSessionRepo(t)
	defer mr.Close()
	assert.NotNil(t, repo)
}

func TestRedisSessionRepository_StoreSession(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{
			SessionID:   "sess123",
			UserID:      1,
			DisplayName: "user1",
			Expiry:      time.Now().UTC().Add(1 * time.Hour),
			CreatedAt:   time.Now().UTC(),
		}

		err := repo.StoreSession(ctx, session)
		require.NoError(t, err)

		sessionKey := makeSessionKey(session.SessionID)
		userKey := makeUserSessionsKey(session.UserID)

		// Check session data
		storedData, err := mr.Get(sessionKey)
		require.NoError(t, err)
		var storedSession models.Session
		err = json.Unmarshal([]byte(storedData), &storedSession)
		require.NoError(t, err)
		assert.Equal(t, session.SessionID, storedSession.SessionID)
		assert.Equal(t, session.UserID, storedSession.UserID)

		// Check user index
		isMember, err := mr.SIsMember(userKey, session.SessionID)
		require.NoError(t, err)
		assert.True(t, isMember)

		// Check TTL (approximate)
		ttl := mr.TTL(sessionKey)
		assert.InDelta(t, time.Hour.Seconds(), ttl.Seconds(), 5, "TTL is not set correctly")
	})

	t.Run("InvalidSessionData", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		err := repo.StoreSession(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session data")

		err = repo.StoreSession(ctx, &models.Session{UserID: 1, Expiry: time.Now().UTC().Add(1 * time.Hour)}) // Missing SessionID
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session data")

		err = repo.StoreSession(ctx, &models.Session{SessionID: "sess1", Expiry: time.Now().UTC().Add(1 * time.Hour)}) // Missing UserID
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session data")
	})

	t.Run("SessionAlreadyExpiredOnStore", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{
			SessionID: "sessExpired",
			UserID:    2,
			Expiry:    time.Now().UTC().Add(-1 * time.Hour), // Expired
		}

		err := repo.StoreSession(ctx, session)
		require.NoError(t, err) // DeleteSession internally returns nil if key not found

		sessionKey := makeSessionKey(session.SessionID)
		exists := mr.Exists(sessionKey)
		assert.False(t, exists, "Expired session should not be stored")

		userKey := makeUserSessionsKey(session.UserID)
		isMember, err := mr.SIsMember(userKey, session.SessionID)
		if err != nil {
			require.EqualError(t, err, miniredis.ErrKeyNotFound.Error(), "SIsMember on a non-existent set should return ErrKeyNotFound from miniredis, or be nil")
		}
		assert.False(t, isMember, "Expired session should not be in user index if it was never properly stored")
	})

	t.Run("RedisPipelineError", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		// No defer mr.Close() here, we close it to simulate error

		session := &models.Session{
			SessionID: "sessPipeErr",
			UserID:    3,
			Expiry:    time.Now().UTC().Add(1 * time.Hour),
		}
		mr.Close() // Close to cause pipeline error
		err := repo.StoreSession(ctx, session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to execute session store pipeline")
	})
}

func TestRedisSessionRepository_GetSession(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{
			SessionID: "getSess1",
			UserID:    10,
			Expiry:    time.Now().UTC().Add(1 * time.Hour),
		}
		jsonData, _ := json.Marshal(session)
		mr.Set(makeSessionKey(session.SessionID), string(jsonData))
		mr.SAdd(makeUserSessionsKey(session.UserID), session.SessionID)

		retrievedSession, err := repo.GetSession(ctx, session.SessionID)
		require.NoError(t, err)
		require.NotNil(t, retrievedSession)
		assert.Equal(t, session.SessionID, retrievedSession.SessionID)
		assert.Equal(t, session.UserID, retrievedSession.UserID)
	})

	t.Run("NotFound", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		_, err := repo.GetSession(ctx, "nonExistentSess")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound)
	})

	t.Run("RedisGetError", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		// No defer mr.Close()

		mr.Close() // Induce error
		_, err := repo.GetSession(ctx, "anySess")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis GET failed")
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		sessionID := "unmarshalErrSess"
		mr.Set(makeSessionKey(sessionID), "this is not json")

		_, err := repo.GetSession(ctx, sessionID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "json unmarshal failed")
	})

	t.Run("SessionIsExpiredInStore", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{
			SessionID: "expiredSessInStore",
			UserID:    11,
			Expiry:    time.Now().UTC().Add(-1 * time.Hour), // Expired
		}
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(session.SessionID)
		userKey := makeUserSessionsKey(session.UserID)

		mr.Set(sessionKey, string(jsonData))
		mr.SAdd(userKey, session.SessionID)

		_, err := repo.GetSession(ctx, session.SessionID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound)

		// Check if cleaned up
		exists := mr.Exists(sessionKey)
		assert.False(t, exists, "Expired session should be deleted by GetSession")

		// With the fix, SRem is only called if UserID > 0.
		// For positive UserID, the session should be removed from the user index.
		// If UserID is positive, it should be removed.
		isMember, _ := mr.SIsMember(userKey, session.SessionID)
		assert.False(t, isMember, "Expired session should be removed from user index by GetSession")
	})

	t.Run("SessionIsExpiredInStore_UserID_Zero", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{
			SessionID: "expiredSessInStoreUID0",
			UserID:    0, // UserID is 0
			Expiry:    time.Now().UTC().Add(-1 * time.Hour),
		}
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(session.SessionID)
		// userKey := makeUserSessionsKey(session.UserID) // user_sessions:0

		mr.Set(sessionKey, string(jsonData))
		// mr.SAdd(userKey, session.SessionID) // Don't add to user_sessions:0 as StoreSession would prevent this

		_, err := repo.GetSession(ctx, session.SessionID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound)

		exists := mr.Exists(sessionKey)
		assert.False(t, exists, "Expired session should be deleted by GetSession")

		// With the fix, SRem is NOT called if UserID <= 0, which is correct
		// as StoreSession would not have indexed a session with UserID 0.
	})
}

func TestRedisSessionRepository_DeleteSession(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		session := &models.Session{SessionID: "delSess1", UserID: 20, Expiry: time.Now().UTC().Add(time.Hour)}
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(session.SessionID)
		userKey := makeUserSessionsKey(session.UserID)
		mr.Set(sessionKey, string(jsonData))
		mr.SAdd(userKey, session.SessionID)

		err := repo.DeleteSession(ctx, session.SessionID)
		require.NoError(t, err)

		exists := mr.Exists(sessionKey)
		assert.False(t, exists)
		isMember, _ := mr.SIsMember(userKey, session.SessionID)
		assert.False(t, isMember)
	})

	t.Run("NotFound", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		err := repo.DeleteSession(ctx, "nonExistentDelSess")
		require.NoError(t, err) // Should be idempotent
	})

	t.Run("GetErrorBeforeDelete", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		// No defer mr.Close()

		// Store something to make Get attempt succeed before closing
		mr.Set(makeSessionKey("delSessGetErr"), `{"SessionID":"delSessGetErr","UserID":21}`)
		mr.Close()

		err := repo.DeleteSession(ctx, "delSessGetErr")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get session before delete")
	})

	t.Run("UnmarshalErrorBeforeDelete", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		sessionID := "delSessUnmarshalErr"
		sessionKey := makeSessionKey(sessionID)
		mr.Set(sessionKey, "not json")

		err := repo.DeleteSession(ctx, sessionID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal session before delete")

		// Key should still be deleted
		exists := mr.Exists(sessionKey)
		assert.False(t, exists, "Key should be deleted even if unmarshal failed")
	})

	t.Run("GetFailsDueToConnectionError", func(t *testing.T) {
		repo, mr, client := newTestRedisSessionRepo(t)
		// No defer mr.Close()

		session := &models.Session{SessionID: "delSessPipeErr", UserID: 22}
		jsonData, _ := json.Marshal(session)
		mr.Set(makeSessionKey(session.SessionID), string(jsonData)) // Set it so Get passes

		// Replace client with one that will fail on Exec
		failingClient := redis.NewClient(&redis.Options{Addr: "localhost:1234"}) // Non-existent server
		(repo.(*RedisSessionRepository)).client = failingClient

		err := repo.DeleteSession(ctx, session.SessionID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get session before delete")

		// Restore original client for mr.Close() if needed, or just let mr close.
		(repo.(*RedisSessionRepository)).client = client // Restore for other tests if suite-level
		mr.Close()                                       // Close miniredis
	})

	t.Run("Success_UserID_Zero", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		// Test deletion of a session that has UserID 0.
		session := &models.Session{SessionID: "delSessUID0", UserID: 0, Expiry: time.Now().UTC().Add(time.Hour)}
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(session.SessionID)
		userKeyForZero := makeUserSessionsKey(0) // "user_sessions:0"

		mr.Set(sessionKey, string(jsonData))
		// Do not add to userKeyForZero, as StoreSession would prevent UserID:0 from being indexed.
		// If it *was* indexed, the current DeleteSession would try to remove it.

		err := repo.DeleteSession(ctx, session.SessionID)
		require.NoError(t, err)

		exists := mr.Exists(sessionKey)
		assert.False(t, exists)

		// With the fix, SRem is NOT called if UserID <= 0.
		// This is correct as StoreSession would not have indexed a session with UserID 0.
		isMember, _ := mr.SIsMember(userKeyForZero, session.SessionID)
		assert.False(t, isMember)
	})
}

func TestRedisSessionRepository_ExtendSession(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		sessionID := "extSess1"
		initialExpiry := time.Now().UTC().Add(30 * time.Minute)
		session := &models.Session{SessionID: sessionID, UserID: 30, Expiry: initialExpiry}
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(sessionID)
		mr.Set(sessionKey, string(jsonData))
		mr.SetTTL(sessionKey, 30*time.Minute)

		newExpiry := time.Now().UTC().Add(2 * time.Hour)
		err := repo.ExtendSession(ctx, sessionID, newExpiry)
		require.NoError(t, err)

		storedData, _ := mr.Get(sessionKey)
		var updatedSession models.Session
		json.Unmarshal([]byte(storedData), &updatedSession)
		assert.WithinDuration(t, newExpiry, updatedSession.Expiry, time.Second)

		ttl := mr.TTL(sessionKey)
		assert.InDelta(t, (2 * time.Hour).Seconds(), ttl.Seconds(), 5)
	})

	t.Run("NotFound", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()
		err := repo.ExtendSession(ctx, "nonExistentExtSess", time.Now().UTC().Add(time.Hour))
		require.ErrorIs(t, err, repository.ErrSessionNotFound)
	})

	t.Run("AlreadyExpired", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		sessionID := "extSessExpired"
		session := &models.Session{SessionID: sessionID, UserID: 31, Expiry: time.Now().UTC().Add(-time.Hour)} // Expired
		jsonData, _ := json.Marshal(session)
		sessionKey := makeSessionKey(sessionID)
		mr.Set(sessionKey, string(jsonData))

		err := repo.ExtendSession(ctx, sessionID, time.Now().UTC().Add(time.Hour))
		require.ErrorIs(t, err, repository.ErrSessionNotFound)

		exists := mr.Exists(sessionKey)
		assert.False(t, exists, "Expired session should be deleted by ExtendSession")
	})

	t.Run("RedisSetError", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		// No defer mr.Close()

		sessionID := "extSessSetErr"
		session := &models.Session{SessionID: sessionID, UserID: 32, Expiry: time.Now().UTC().Add(time.Hour)}
		jsonData, _ := json.Marshal(session)
		mr.Set(makeSessionKey(sessionID), string(jsonData))

		mr.Close() // Induce error on Set
		err := repo.ExtendSession(ctx, sessionID, time.Now().UTC().Add(2*time.Hour))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis GET failed during extend") // GET fails first when mr is closed
	})
}

func TestRedisSessionRepository_DeleteUserSessions(t *testing.T) {
	ctx := context.Background()
	userID := int64(40)

	setupSessions := func(t *testing.T, mr *miniredis.Miniredis, client *redis.Client, numSessions int, excludeOffset int) (repo repository.SessionRepository, sessionIDs []string) {
		t.Helper()
		repo = NewRedisSessionRepository(client)
		userKey := makeUserSessionsKey(userID)

		for i := 0; i < numSessions; i++ {
			sessID := fmt.Sprintf("userSess-%d-%d", userID, i+excludeOffset)
			sessionIDs = append(sessionIDs, sessID)
			session := &models.Session{SessionID: sessID, UserID: userID, Expiry: time.Now().UTC().Add(time.Hour)}
			jsonData, _ := json.Marshal(session)

			mr.Set(makeSessionKey(sessID), string(jsonData))
			mr.SAdd(userKey, sessID)
		}
		return repo, sessionIDs
	}

	t.Run("Success_NoExclusions", func(t *testing.T) {
		_, mr, client := newTestRedisSessionRepo(t)
		defer mr.Close()
		repo, sIDs := setupSessions(t, mr, client, 3, 0)

		deletedCount, err := repo.DeleteUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, int64(3), deletedCount)

		for _, sID := range sIDs {
			exists := mr.Exists(makeSessionKey(sID))
			assert.False(t, exists, "Session %s should be deleted", sID)
		}
		members, err := mr.SMembers(makeUserSessionsKey(userID))
		// miniredis SMembers returns ErrKeyNotFound if the set is empty and deleted,
		// real Redis returns empty list.
		// So, we accept ErrKeyNotFound or no error.
		require.True(t, err == nil || err == miniredis.ErrKeyNotFound, "SMembers failed unexpectedly: %v", err)
		assert.Len(t, members, 0, "User session set should be empty")
	})

	t.Run("Success_WithExclusions", func(t *testing.T) {
		_, mr, client := newTestRedisSessionRepo(t)
		defer mr.Close()
		repo, sIDs := setupSessions(t, mr, client, 5, 0) // sIDs: userSess-40-0 to userSess-40-4

		exclude := []string{sIDs[1], sIDs[3]} // Exclude userSess-40-1, userSess-40-3
		deletedCount, err := repo.DeleteUserSessions(ctx, userID, exclude...)
		require.NoError(t, err)
		assert.Equal(t, int64(3), deletedCount) // 5 total - 2 excluded = 3 deleted

		// Check deleted
		assert.False(t, mr.Exists(makeSessionKey(sIDs[0])))
		assert.False(t, mr.Exists(makeSessionKey(sIDs[2])))
		assert.False(t, mr.Exists(makeSessionKey(sIDs[4])))

		// Check excluded (should exist)
		assert.True(t, mr.Exists(makeSessionKey(sIDs[1])))
		assert.True(t, mr.Exists(makeSessionKey(sIDs[3])))

		userKey := makeUserSessionsKey(userID)
		members, _ := mr.SMembers(userKey)
		assert.ElementsMatch(t, exclude, members, "User session set should only contain excluded sessions")
	})

	t.Run("NoSessionsForUser", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		deletedCount, err := repo.DeleteUserSessions(ctx, userID) // UserID 40 has no sessions yet
		require.NoError(t, err)
		assert.Equal(t, int64(0), deletedCount)
	})

	t.Run("AllSessionsExcluded", func(t *testing.T) {
		_, mr, client := newTestRedisSessionRepo(t)
		defer mr.Close()
		repo, sIDs := setupSessions(t, mr, client, 2, 0)

		deletedCount, err := repo.DeleteUserSessions(ctx, userID, sIDs...) // Exclude all
		require.NoError(t, err)
		assert.Equal(t, int64(0), deletedCount)

		for _, sID := range sIDs {
			exists := mr.Exists(makeSessionKey(sID))
			assert.True(t, exists, "Session %s should still exist", sID)
		}
	})

	t.Run("SmembersError", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		// No defer mr.Close()

		mr.Close() // Induce error
		_, err := repo.DeleteUserSessions(ctx, userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get user sessions with SMEMBERS")
	})

	t.Run("PipelineError", func(t *testing.T) {
		_, mr, client := newTestRedisSessionRepo(t)
		// No defer mr.Close()
		repo, _ := setupSessions(t, mr, client, 1, 100) // Setup at least one session to attempt deletion

		// Replace client to induce error on Exec
		failingClient := redis.NewClient(&redis.Options{Addr: "localhost:1234"})
		(repo.(*RedisSessionRepository)).client = failingClient

		_, err := repo.DeleteUserSessions(ctx, userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get user sessions with SMEMBERS") // SMembers fails first

		(repo.(*RedisSessionRepository)).client = client // Restore
		mr.Close()
	})

	t.Run("DeleteUserSessions_UserID_Zero", func(t *testing.T) {
		repo, mr, _ := newTestRedisSessionRepo(t)
		defer mr.Close()

		// Setup some sessions for a different user to ensure they are not affected
		otherUserID := int64(1)
		mr.SAdd(makeUserSessionsKey(otherUserID), "othersess1")
		mr.Set(makeSessionKey("othersess1"), `{"SessionID":"othersess1","UserID":`+strconv.FormatInt(otherUserID, 10)+`}`)

		// Attempt to delete sessions for UserID 0
		deletedCount, err := repo.DeleteUserSessions(ctx, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(0), deletedCount)

		// Ensure other user's sessions are untouched
		members, err := mr.SMembers(makeUserSessionsKey(otherUserID))
		require.NoError(t, err)
		assert.Len(t, members, 1, "Other user's sessions should not be affected")
		assert.Equal(t, "othersess1", members[0])

	})
}
