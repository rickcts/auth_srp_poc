package mocks

import (
	"context"

	"github.com/rickcts/srp/internal/models"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// MockOAuthService is a mock implementation of the OAuthService interface.
// Use this for testing handlers or other components that depend on OAuthService.
type MockOAuthService struct {
	mock.Mock
}

// GetAuthCodeURL provides a mock function for generating the auth code URL.
func (m *MockOAuthService) GetAuthCodeURL(state string) string {
	args := m.Called(state)
	return args.String(0)
}

// ExchangeCode provides a mock function for exchanging an auth code for a token.
func (m *MockOAuthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	args := m.Called(ctx, code)
	// Handle potential nil return for the token
	token, _ := args.Get(0).(*oauth2.Token)
	return token, args.Error(1)
}

// GetUserInfo provides a mock function for fetching user info using a token.
func (m *MockOAuthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*models.OAuthUser, error) {
	args := m.Called(ctx, token)
	// Handle potential nil return for the user
	user, _ := args.Get(0).(*models.OAuthUser)
	return user, args.Error(1)
}
