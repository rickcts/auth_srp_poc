package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockUserGenerator is a mock implementation of the UserGenerator interface.
type MockUserGenerator struct {
	mock.Mock
}

func (m *MockUserGenerator) UpdateUserInfo(ctx context.Context, authID, displayName string) error {
	args := m.Called(ctx, authID, displayName)
	return args.Error(0)
}

func (m *MockUserGenerator) DeleteUser(ctx context.Context, authID string) error {
	args := m.Called(ctx, authID)
	return args.Error(0)
}
