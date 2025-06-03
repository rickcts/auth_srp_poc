package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateToken(userID int64) (string, time.Time, error) {
	args := m.Called(userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}
