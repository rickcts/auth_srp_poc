package mocks

import (
	"context"

	"github.com/rickcts/srp/internal/models"

	"github.com/stretchr/testify/mock"
)

type MockSRPAuthService struct {
	mock.Mock
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
