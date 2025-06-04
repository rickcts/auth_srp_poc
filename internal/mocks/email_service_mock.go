package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, toEmail, resetCode, resetContextInfo string) error {
	args := m.Called(ctx, toEmail, resetCode, resetContextInfo)
	return args.Error(0)
}

func (m *MockEmailService) SendActivationEmail(ctx context.Context, toEmail, activationCode, appName string) error {
	args := m.Called(ctx, toEmail, activationCode, appName)
	return args.Error(0)
}
