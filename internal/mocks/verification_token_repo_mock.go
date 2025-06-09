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
func (_m *MockVerificationTokenRepository) StorePasswordResetToken(ctx context.Context, authID string, token string, expiryTime time.Duration) error {
	ret := _m.Called(ctx, authID, token, expiryTime)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Duration) error); ok {
		r0 = rf(ctx, authID, token, expiryTime)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateAndConsumePasswordResetToken provides a mock function with given fields: ctx, authIDFromRequest, tokenFromRequest
func (_m *MockVerificationTokenRepository) ValidateAndConsumePasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	ret := _m.Called(ctx, authIDFromRequest, tokenFromRequest)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// GetAuthIDForValidPasswordResetToken provides a mock function with given fields: ctx, authIDFromRequest, tokenFromRequest
func (_m *MockVerificationTokenRepository) GetAuthIDForValidPasswordResetToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	ret := _m.Called(ctx, authIDFromRequest, tokenFromRequest)
	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r0 = ret.Get(0).(string)
	}
	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// DeletePasswordResetTokensForAuthID provides a mock function with given fields: ctx, authID
func (_m *MockVerificationTokenRepository) DeletePasswordResetTokensForAuthID(ctx context.Context, authID string) error {
	ret := _m.Called(ctx, authID)
	return ret.Error(0)
}

// StoreActivationToken provides a mock function with given fields: ctx, authID, code, expiry
func (_m *MockVerificationTokenRepository) StoreActivationToken(ctx context.Context, authID string, code string, expiry time.Duration) error {
	ret := _m.Called(ctx, authID, code, expiry)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Duration) error); ok {
		r0 = rf(ctx, authID, code, expiry)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ValidateAndConsumeActivationToken provides a mock function with given fields: ctx, authIDFromRequest, tokenFromRequest
func (_m *MockVerificationTokenRepository) ValidateAndConsumeActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	ret := _m.Called(ctx, authIDFromRequest, tokenFromRequest)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// GetAuthIDForValidActivationToken provides a mock function with given fields: ctx, authIDFromRequest, tokenFromRequest
func (_m *MockVerificationTokenRepository) GetAuthIDForValidActivationToken(ctx context.Context, authIDFromRequest string, tokenFromRequest string) (string, error) {
	ret := _m.Called(ctx, authIDFromRequest, tokenFromRequest)
	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r0 = ret.Get(0).(string)
	}
	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, authIDFromRequest, tokenFromRequest)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// DeleteActivationTokensForAuthID provides a mock function with given fields: ctx, authID
func (_m *MockVerificationTokenRepository) DeleteActivationTokensForAuthID(ctx context.Context, authID string) error {
	ret := _m.Called(ctx, authID)
	return ret.Error(0)
}
