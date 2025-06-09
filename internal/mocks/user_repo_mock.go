package mocks

import (
	"context"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, authId, displayName, authProvider string, authExtras any) error {
	args := m.Called(ctx, authId, displayName, authProvider, authExtras)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserInfoByAuthID(ctx context.Context, authId string) (userInfo *models.UserInfo, err error) {
	args := m.Called(ctx, authId)
	val := args.Get(0)
	if val != nil {
		userInfo = val.(*models.UserInfo)
	}
	return userInfo, args.Error(1)
}

func (m *MockUserRepository) CheckIfUserExists(ctx context.Context, authId string) (bool, error) {
	args := m.Called(ctx, authId) // <--- CORRECTED
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) ActivateUser(ctx context.Context, userId int64) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateUserSRPAuth(ctx context.Context, authId string, newSaltHex string, newVerifierHex string) error {
	args := m.Called(ctx, authId, newSaltHex, newVerifierHex)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateActivationCode(ctx context.Context, authID string, code string, expiry time.Time) error {
	args := m.Called(ctx, authID, code, expiry)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateUserInfoByAuthID(ctx context.Context, authID string, displayName string) error {
	args := m.Called(ctx, authID, displayName)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, authID string) error {
	args := m.Called(ctx, authID)
	return args.Error(0)
}

func (m *MockUserRepository) CreateUserAuthEvent(ctx context.Context, host string, errorCode int) error {
	args := m.Called(ctx, host, errorCode)
	return args.Error(0)
}
