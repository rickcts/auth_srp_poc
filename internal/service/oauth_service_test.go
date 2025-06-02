package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/mocks"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// --- Test Setup ---

func setupTestConfig() *config.Config {
	return &config.Config{
		OAuthProviders: map[string]*oauth2.Config{
			"MICROSOFT": {
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost/callback",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
					TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
				},
				Scopes: []string{"openid", "profile", "email", "offline_access"},
			},
		},
	}
}

// --- Test Cases ---

func TestNewMSOAuthService(t *testing.T) {
	cfg := setupTestConfig()
	mockRepo := new(mocks.MockUserRepository)
	service := NewMSOAuthService(cfg, mockRepo)

	assert.NotNil(t, service)
	assert.Equal(t, mockRepo, service.userRepo)
	assert.Equal(t, cfg, service.cfg)
	assert.Equal(t, cfg.OAuthProviders["MICROSOFT"], service.oAuthConfig)
	assert.Equal(t, "https://graph.microsoft.com/v1.0/me", service.api)
}

func TestGetAuthCodeURL(t *testing.T) {
	cfg := setupTestConfig()
	service := NewMSOAuthService(cfg, nil) // No repo needed
	state := "test-state-123"

	url := service.GetAuthCodeURL(state)

	assert.Contains(t, url, cfg.OAuthProviders["MICROSOFT"].Endpoint.AuthURL)
	assert.Contains(t, url, "client_id=test-client-id")
	assert.Contains(t, url, "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback")
	assert.Contains(t, url, "response_type=code")
	assert.Contains(t, url, "scope=openid+profile+email+offline_access")
	assert.Contains(t, url, "state=test-state-123")
	assert.Contains(t, url, "access_type=offline")
}

func TestExchangeCode_Success(t *testing.T) {
	cfg := setupTestConfig()
	service := NewMSOAuthService(cfg, nil)

	// Mock the HTTP server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"access_token":"test_access_token","token_type":"Bearer","refresh_token":"test_refresh_token","expires_in":3600, "id_token":"mock_id_token"}`)
	}))
	defer server.Close()

	// Override the TokenURL to use the mock server
	service.oAuthConfig.Endpoint.TokenURL = server.URL

	token, err := service.ExchangeCode(context.Background(), "test-code")

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test_access_token", token.AccessToken)
	assert.True(t, token.Valid())
}

func TestExchangeCode_Failure(t *testing.T) {
	cfg := setupTestConfig()
	service := NewMSOAuthService(cfg, nil)

	// Mock the HTTP server to return an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()

	service.oAuthConfig.Endpoint.TokenURL = server.URL

	token, err := service.ExchangeCode(context.Background(), "bad-code")

	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to exchange code")
}

func TestExchangeCodeMobile_Success(t *testing.T) {
	cfg := setupTestConfig()
	service := NewMSOAuthService(cfg, nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(t, err)
		assert.Equal(t, "test_verifier", r.Form.Get("code_verifier")) // Check if verifier is sent
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"access_token":"test_mobile_token","token_type":"Bearer","expires_in":3600, "id_token":"mock_id_token"}`)
	}))
	defer server.Close()

	service.oAuthConfig.Endpoint.TokenURL = server.URL

	token, err := service.ExchangeCodeMobile(context.Background(), "test-code-mobile", "test_verifier", "MICROSOFT")

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test_mobile_token", token.AccessToken)
	assert.True(t, token.Valid())
}
