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
func (m *MockSessionRepository) DeleteUserSessions(ctx context.Context, userId int64, excludeTokenIDs ...string) (int64, error) {
	// To handle variadic arguments correctly with testify/mock,
	// we need to pass them as a slice of interface{} if we want to match them specifically,
	// or use mock.Anything if the content of excludeTokenIDs doesn't matter for a specific test.
	// For a general mock, converting to []interface{} is safer for Called().
	variadicArgs := make([]interface{}, len(excludeTokenIDs))
	for i, v := range excludeTokenIDs {
		variadicArgs[i] = v
	}
	callArgs := append([]interface{}{ctx, userId}, variadicArgs...)
	args := m.Called(callArgs...)
	return args.Get(0).(int64), args.Error(1)
}
