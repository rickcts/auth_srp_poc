package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockPasswordResetTokenRepository is a mock type for the PasswordResetTokenRepository type
type MockPasswordResetTokenRepository struct {
	mock.Mock
}

// StoreResetToken provides a mock function with given fields: ctx, authID, token, expiryTime
func (_m *MockPasswordResetTokenRepository) StoreResetToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	ret := _m.Called(ctx, authID, token, expiryTime)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Time) error); ok {
		r0 = rf(ctx, authID, token, expiryTime)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateAndConsumeResetToken provides a mock function with given fields: ctx, token
func (_m *MockPasswordResetTokenRepository) ValidateAndConsumeResetToken(ctx context.Context, token string) (string, error) {
	ret := _m.Called(ctx, token)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
