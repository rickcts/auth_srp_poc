package mocks

import (
	"context"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"

	"github.com/stretchr/testify/mock"
)

type MockSRPAuthService struct {
	mock.Mock
}

func (m *MockSRPAuthService) CheckIfUserExists(ctx context.Context, req models.AuthIDRequest) (bool, error) {
	args := m.Called(req)
	return args.Bool(0), args.Error(1)
}

func (m *MockSRPAuthService) Register(ctx context.Context, req models.SRPRegisterRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *MockSRPAuthService) ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error) {
	args := m.Called(req)
	resp, _ := args.Get(0).(*models.AuthStep1Response)
	return resp, args.Error(1)
}

func (m *MockSRPAuthService) VerifyClientProof(ctx context.Context, req models.AuthStep2Request) (*models.AuthStep3Response, error) {
	args := m.Called(req)
	resp, _ := args.Get(0).(*models.AuthStep3Response)
	return resp, args.Error(1)
}

func (m *MockSRPAuthService) InitiatePasswordReset(ctx context.Context, req models.InitiatePasswordResetRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockSRPAuthService) CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *MockSRPAuthService) ValidatePasswordResetToken(ctx context.Context, req models.ValidatePasswordResetTokenRequest) (*models.ValidatePasswordResetTokenResponse, error) {
	args := m.Called(ctx, req)
	resp, _ := args.Get(0).(*models.ValidatePasswordResetTokenResponse)
	return resp, args.Error(1)
}

func (m *MockSRPAuthService) InitiatePasswordChangeVerification(ctx context.Context, authID string) (*models.InitiateChangePasswordResponse, error) {
	args := m.Called(ctx, authID)
	resp, _ := args.Get(0).(*models.InitiateChangePasswordResponse)
	return resp, args.Error(1)
}
func (m *MockSRPAuthService) ConfirmPasswordChange(ctx context.Context, authID string, req models.ConfirmChangePasswordRequest) error {
	args := m.Called(ctx, authID, req)
	return args.Error(0)
}

func (m *MockSRPAuthService) GenerateCodeAndSendActivationEmail(ctx context.Context, req models.AuthIDRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockSRPAuthService) ActivateUser(ctx context.Context, req models.ActivateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
