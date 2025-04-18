package mocks

import (
	"github.com/stretchr/testify/mock"
)

type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateToken(username string) (string, error) {
	args := m.Called(username)
	return args.String(0), args.Error(1)
}
