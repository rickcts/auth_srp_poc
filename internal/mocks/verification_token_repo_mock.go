package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockVerificationTokenRepository is a mock type for the VerificationTokenRepository type
type MockVerificationTokenRepository struct {
	mock.Mock
}

// StorePasswordResetToken provides a mock function with given fields: ctx, authID, token, expiryTime
func (_m *MockVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiryTime time.Time) error {
	ret := _m.Called(ctx, authID, token, expiryTime)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Time) error); ok {
		r0 = rf(ctx, authID, token, expiryTime)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateAndConsumePasswordResetToken provides a mock function with given fields: ctx, token
func (_m *MockVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
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

// GetAuthIDForValidPasswordResetToken provides a mock function with given fields: ctx, token
func (_m *MockVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, token string) (string, error) {
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

func (_m *MockVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, token string) (string, error) {
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

// StoreActivationToken provides a mock function with given fields: ctx, authID, code, expiry
func (_m *MockVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, code string, expiry time.Time) error {
	ret := _m.Called(ctx, authID, code, expiry)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Time) error); ok {
		r0 = rf(ctx, authID, code, expiry)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ValidateAndConsumeActivationToken provides a mock function with given fields: ctx, token
func (_m *MockVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, token string) (string, error) {
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
