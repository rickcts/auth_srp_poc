package mocks

import (
	"context"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/stretchr/testify/mock"
)

// MockSessionGenerator is a mock type for the SessionGenerator type
type MockSessionGenerator struct {
	mock.Mock
}

// VerifySessionToken provides a mock function with given fields: ctx, sessionTokenID
func (_m *MockSessionGenerator) VerifySessionToken(ctx context.Context, sessionTokenID string) (*models.VerifyTokenResponse, error) {
	ret := _m.Called(ctx, sessionTokenID)

	var r0 *models.VerifyTokenResponse
	if rf, ok := ret.Get(0).(func(context.Context, string) *models.VerifyTokenResponse); ok {
		r0 = rf(ctx, sessionTokenID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.VerifyTokenResponse)
		}
	}
	return r0, ret.Error(1)
}

// GetUserSessions provides a mock function with given fields: ctx, sessionTokenID
func (_m *MockSessionGenerator) GetUserSessions(ctx context.Context, sessionTokenID string) (*models.GetUserSessionsResponse, error) {
	ret := _m.Called(ctx, sessionTokenID)

	var r0 *models.GetUserSessionsResponse
	if rf, ok := ret.Get(0).(func(context.Context, string) *models.GetUserSessionsResponse); ok {
		r0 = rf(ctx, sessionTokenID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.GetUserSessionsResponse)
		}
	}
	return r0, ret.Error(1)
}

// ExtendUserSession provides a mock function with given fields: ctx, currentSessionToken
func (_m *MockSessionGenerator) ExtendUserSession(ctx context.Context, currentSessionToken string) (*models.ExtendedSessionResponse, error) {
	ret := _m.Called(ctx, currentSessionToken)

	var r0 *models.ExtendedSessionResponse
	if rf, ok := ret.Get(0).(func(context.Context, string) *models.ExtendedSessionResponse); ok {
		r0 = rf(ctx, currentSessionToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.ExtendedSessionResponse)
		}
	}
	return r0, ret.Error(1)
}

// SignOut provides a mock function with given fields: ctx, sessionToken
func (_m *MockSessionGenerator) SignOut(ctx context.Context, sessionToken string) error {
	ret := _m.Called(ctx, sessionToken)
	return ret.Error(0)
}

// SignOutUserSessions provides a mock function with given fields: ctx, userId, currentSessionTokenToExclude
func (_m *MockSessionGenerator) SignOutUserSessions(ctx context.Context, authID string, currentSessionTokenToExclude ...string) (int64, error) {
	// The variadic argument needs to be handled carefully with testify/mock.
	// One way is to pass it as a slice.
	var args []interface{}
	args = append(args, ctx, authID)
	for _, token := range currentSessionTokenToExclude {
		args = append(args, token)
	}
	ret := _m.Called(args...)

	return ret.Get(0).(int64), ret.Error(1)
}
