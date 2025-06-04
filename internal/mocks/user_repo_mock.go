package mocks

import (
	"context"

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
	return args.Get(0).(*models.UserInfo), args.Error(1)
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
