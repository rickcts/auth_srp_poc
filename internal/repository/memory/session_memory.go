package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

// MemorySessionRepository implements SessionRepository in memory (NOT FOR PRODUCTION).
type MemorySessionRepository struct {
	sessions      map[string]models.Session
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	userSessions  map[int64]map[string]struct{} // UserID -> {SessionID: {}}
}

// NewMemorySessionRepository creates a new in-memory session repository.
// cleanupInterval defines how often expired sessions are automatically removed.
func NewMemorySessionRepository(cleanupInterval time.Duration) repository.SessionRepository {
	r := &MemorySessionRepository{
		sessions:      make(map[string]models.Session),
		cleanupTicker: time.NewTicker(cleanupInterval),
		userSessions:  make(map[int64]map[string]struct{}),
		stopCleanup:   make(chan struct{}),
	}
	go r.startCleanup()
	return r
}

// startCleanup runs the periodic cleanup in a background goroutine.
func (r *MemorySessionRepository) startCleanup() {
	for {
		select {
		case <-r.cleanupTicker.C:
			r.cleanupExpiredSessions()
		case <-r.stopCleanup:
			r.cleanupTicker.Stop()
			return
		}
	}
}

// cleanupExpiredSessions removes all expired sessions and updates user indexes.
func (r *MemorySessionRepository) cleanupExpiredSessions() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	expiredIDs := []string{}

	// IDentify expired sessions
	for SessionID, session := range r.sessions {
		if now.After(session.Expiry) {
			expiredIDs = append(expiredIDs, SessionID)
		}
	}

	// Delete expired sessions and remove from user index
	for _, SessionID := range expiredIDs {
		session, exists := r.sessions[SessionID]
		if exists { // Double check existence in case it was deleted by another cleanup cycle
			delete(r.sessions, SessionID)
			if session.UserID > 0 {
				if userSessions, ok := r.userSessions[session.UserID]; ok {
					delete(userSessions, SessionID)
					if len(userSessions) == 0 {
						delete(r.userSessions, session.UserID)
					}
				}
			}
		}
	}
}

// StopCleanup stops the background cleanup task.
func (r *MemorySessionRepository) StopCleanup() {
	close(r.stopCleanup)
}

// StoreSession saves or updates a session.
func (r *MemorySessionRepository) StoreSession(ctx context.Context, session *models.Session) error {
	if session == nil || session.SessionID == "" {
		return errors.New("invalID session data") // Basic valIDation
	}
	if session.UserID <= 0 {
		return errors.New("session UserID must be set")
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.sessions[session.SessionID] = *session
	r.addUserSessionIndex(session.UserID, session.SessionID)

	return nil
}

// GetSession retrieves a session by its ID.
func (r *MemorySessionRepository) GetSession(ctx context.Context, SessionID string) (*models.Session, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	session, exists := r.sessions[SessionID]
	if !exists || session.IsExpired() {
		return nil, repository.ErrSessionNotFound
	}
	return &session, nil
}

// GetSessions retrieves all sessions for a given user ID.
func (r *MemorySessionRepository) GetSessions(ctx context.Context, userID int64) ([]*models.Session, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	SessionIDs, exists := r.userSessions[userID]
	if !exists || len(SessionIDs) == 0 {
		return []*models.Session{}, nil
	}

	var sessions []*models.Session
	// Iterate over the session IDs for this user
	for SessionID := range SessionIDs {
		// Retrieve the actual session data
		session, exists := r.sessions[SessionID]
		if exists && !session.IsExpired() {
			sessions = append(sessions, &session)
		} else {
			// If session doesn't exist or is expired, it should be cleaned up later.
			// For now, we just don't include it in the result.
		}
	}

	return sessions, nil
}

// DeleteSession removes a session.
func (r *MemorySessionRepository) DeleteSession(ctx context.Context, SessionID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	session, exists := r.sessions[SessionID]
	if exists {
		delete(r.sessions, SessionID)
		r.removeUserSessionIndex(session.UserID, SessionID)
	}
	return nil
}

// ExtendSession updates the expiry time for a session.
func (r *MemorySessionRepository) ExtendSession(ctx context.Context, SessionID string, newExpiry time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	session, exists := r.sessions[SessionID]
	if !exists || session.IsExpired() {
		return repository.ErrSessionNotFound
	}

	session.Expiry = newExpiry
	r.sessions[SessionID] = session
	return nil
}

// DeleteUserSessions deletes all sessions for a user, optionally excluding some.
func (r *MemorySessionRepository) DeleteUserSessions(ctx context.Context, UserID int64, excludeTokenIDs ...string) (int64, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	SessionIDs, exists := r.userSessions[UserID]
	if !exists || len(SessionIDs) == 0 {
		return 0, nil
	}

	excludeMap := make(map[string]struct{}, len(excludeTokenIDs))
	for _, ID := range excludeTokenIDs {
		excludeMap[ID] = struct{}{}
	}

	deletedCount := int64(0)
	SessionIDsToDelete := []string{}

	for SessionID := range SessionIDs {
		if _, shouldExclude := excludeMap[SessionID]; !shouldExclude {
			SessionIDsToDelete = append(SessionIDsToDelete, SessionID)
		}
	}

	for _, SessionID := range SessionIDsToDelete {
		delete(r.sessions, SessionID)
		delete(r.userSessions[UserID], SessionID)
		deletedCount++
	}

	if len(r.userSessions[UserID]) == 0 {
		delete(r.userSessions, UserID)
	}

	return deletedCount, nil
}

func (r *MemorySessionRepository) addUserSessionIndex(UserID int64, SessionID string) {
	if _, ok := r.userSessions[UserID]; !ok {
		r.userSessions[UserID] = make(map[string]struct{})
	}
	r.userSessions[UserID][SessionID] = struct{}{}
}

func (r *MemorySessionRepository) removeUserSessionIndex(UserID int64, SessionID string) {
	if userSessions, ok := r.userSessions[UserID]; ok {
		delete(userSessions, SessionID)
		if len(userSessions) == 0 {
			delete(r.userSessions, UserID)
		}
	}
}
