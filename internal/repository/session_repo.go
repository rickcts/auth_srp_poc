package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
)

// ErrSessionNotFound is returned when a session ID is not found or has expired.
var ErrSessionNotFound = errors.New("session not found or expired")

// SessionRepository defines the interface for managing user login sessions.
type SessionRepository interface {
	// StoreSession saves a new session or updates an existing one.
	StoreSession(ctx context.Context, session *models.Session) error
	// GetSession retrieves a session by its ID.
	// It should return ErrSessionNotFound if the session doesn't exist or is expired.
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)
	// DeleteSession removes a session, effectively logging the user out.
	DeleteSession(ctx context.Context, sessionID string) error
	// ExtendSession updates the expiry time of an existing session (for sliding sessions).
	ExtendSession(ctx context.Context, sessionID string, newExpiry time.Time) error
	// DeleteUserSessions facilitates "logout all devices" or "logout specific other devices".
	// It should delete all session records for a given userID, optionally excluding some tokenIDs.
	DeleteUserSessions(ctx context.Context, userID int64, excludeTokenIDs ...string) (int64, error)
}
