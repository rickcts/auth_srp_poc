package mocks

import (
	"context"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"

	"github.com/stretchr/testify/mock"
)

type MockStateRepository struct {
	mock.Mock
}

func (m *MockStateRepository) StoreAuthState(ctx context.Context, authID string, state models.AuthSessionState) error {
	args := m.Called(authID, state)
	return args.Error(0)
}

func (m *MockStateRepository) GetAuthState(ctx context.Context, authID string) (*models.AuthSessionState, error) {
	args := m.Called(authID)
	state, _ := args.Get(0).(*models.AuthSessionState) // Handle nil case if needed
	return state, args.Error(1)
}

func (m *MockStateRepository) DeleteAuthState(ctx context.Context, authID string) error {
	args := m.Called(authID)
	return args.Error(0)
}
