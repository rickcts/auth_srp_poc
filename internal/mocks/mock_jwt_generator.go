package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

// MockJWTGenerator is a mock type for the JWTGenerator type
type MockJWTGenerator struct {
	mock.Mock
}

// GenerateToken provides a mock function with given fields: authID
func (_m *MockJWTGenerator) GenerateToken(authID string) (string, time.Time, error) {
	ret := _m.Called(authID)

	return ret.Get(0).(string), ret.Get(1).(time.Time), ret.Error(2)
}
