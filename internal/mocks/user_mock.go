package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUserCreds(ctx context.Context, username, saltHex, verifierHex string) error {
	args := m.Called(username, saltHex, verifierHex)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserCredsByUsername(ctx context.Context, username string) (string, string, error) {
	args := m.Called(username)
	return args.String(0), args.String(1), args.Error(2)
}
