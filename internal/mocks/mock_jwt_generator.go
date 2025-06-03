package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

// MockJWTGenerator is a mock type for the JWTGenerator type
type MockJWTGenerator struct {
	mock.Mock
}

// GenerateToken provides a mock function with given fields: userId
func (_m *MockJWTGenerator) GenerateToken(userId int64) (string, time.Time, error) {
	ret := _m.Called(userId)

	return ret.Get(0).(string), ret.Get(1).(time.Time), ret.Error(2)
}
