package mocks

import (
	"context"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/stretchr/testify/mock"
)

// MockSessionRepository is a mock implementation of the SessionRepository interface.
type MockSessionRepository struct {
	mock.Mock
}

// StoreSession provides a mock function for storing a session.
func (m *MockSessionRepository) StoreSession(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

// GetSession provides a mock function for retrieving a session.
func (m *MockSessionRepository) GetSession(ctx context.Context, sessionId string) (*models.Session, error) {
	args := m.Called(ctx, sessionId)
	session, _ := args.Get(0).(*models.Session) // Handle nil case if Get(0) is not *models.Session
	return session, args.Error(1)
}

// GetSessions provides a mock function for retrieving all sessions for a user.
func (m *MockSessionRepository) GetSessions(ctx context.Context, userID int64) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	sessions, _ := args.Get(0).([]*models.Session) // Handle nil case
	return sessions, args.Error(1)
}

// DeleteSession provides a mock function for deleting a session.
func (m *MockSessionRepository) DeleteSession(ctx context.Context, sessionId string) error {
	args := m.Called(ctx, sessionId)
	return args.Error(0)
}

// ExtendSession provides a mock function for extending a session's expiry.
func (m *MockSessionRepository) ExtendSession(ctx context.Context, sessionId string, newExpiry time.Time) error {
	args := m.Called(ctx, sessionId, newExpiry)
	return args.Error(0)
}

// DeleteUserSessions provides a mock function for deleting all sessions for a user, with optional exclusions.
func (m *MockSessionRepository) DeleteUserSessions(ctx context.Context, userID int64, excludeTokenIDs ...string) (int64, error) {
	variadicArgs := make([]interface{}, len(excludeTokenIDs))
	for i, v := range excludeTokenIDs {
		variadicArgs[i] = v
	}
	callArgs := append([]interface{}{ctx, userID}, variadicArgs...)
	args := m.Called(callArgs...)
	return args.Get(0).(int64), args.Error(1)
}
