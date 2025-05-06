package handler_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/handler"
	"github.com/rickcts/srp/internal/mocks" // Assuming mocks are in this package
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// Helper to setup OAuth test app
func setupOAuthTestApp(mockOAuthService *mocks.MockOAuthService, cfg *config.Config) *fiber.App {
	app := fiber.New()
	oauthHandler := handler.NewOAuthHandler(mockOAuthService, cfg)
	// Assuming router setup function exists or setting up manually
	router.SetupOAuthRoutes(app, oauthHandler) // Use if available
	return app
}

// Helper to create a test config
func createTestOAuthConfig() *config.Config {
	return &config.Config{
		StateCookieName: "test_oauth_state",
	}
}

func TestOAuthHandler_Login(t *testing.T) {
	mockOAuthService := new(mocks.MockOAuthService)
	cfg := createTestOAuthConfig()
	app := setupOAuthTestApp(mockOAuthService, cfg)

	expectedRedirectURLBase := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid+profile+email&state="

	mockReturnedState := "fixed-mock-state-for-test-123"
	mockReturnedURL := expectedRedirectURLBase + mockReturnedState

	mockOAuthService.On("GetAuthCodeURL", mock.MatchedBy(func(state string) bool {
		return state != "" // Ensure the handler is passing a state
	})).Return(mockReturnedURL).Once()

	// Create the HTTP request
	req := httptest.NewRequest("GET", "/api/auth/oauth/microsoft/login", nil)
	resp, err := app.Test(req, -1)

	// --- Assertions ---
	require.NoError(t, err, "app.Test should not return an error")
	// Ensure the response body is closed even if later assertions fail
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	require.NotNil(t, resp, "Response should not be nil")
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode, "Expected status code 307 Temporary Redirect")

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "Location header should be set for redirect")
	assert.True(t, strings.HasPrefix(location, expectedRedirectURLBase), "Redirect URL should start with the expected base path and query params")

	cookies := resp.Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.StateCookieName {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie '%s' should be set", cfg.StateCookieName)
	require.NotEmpty(t, stateCookie.Value, "State cookie value should not be empty") // Use require here
	assert.True(t, stateCookie.HttpOnly, "State cookie should be HttpOnly")
	assert.Equal(t, http.SameSiteLaxMode, stateCookie.SameSite, "State cookie SameSite should be Lax")
	expectedExpiry := time.Now().Add(10 * time.Minute)

	assert.WithinDuration(t, expectedExpiry, stateCookie.Expires, 20*time.Second, "State cookie expiry is incorrect")

	assert.Equal(t, mockReturnedURL, location, "Location header should match the URL returned by the mocked service")

	mockOAuthService.AssertExpectations(t)
}

func TestOAuthHandler_Callback(t *testing.T) {
	mockOAuthService := new(mocks.MockOAuthService)
	cfg := createTestOAuthConfig()
	setupOAuthTestApp(mockOAuthService, cfg)

	testState := uuid.NewString()
	testCode := "valid-auth-code"
	testToken := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
		TokenType:    "Bearer",
	}
	testUser := &models.OAuthUser{
		ID:          "user-123",
		DisplayName: "Test User",
		Email:       "test@example.com",
	}

	t.Run("Success", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg) // Recreate app with fresh mock

		// Mock service calls
		mockOAuthService.On("ExchangeCode", mock.Anything, testCode).Return(testToken, nil).Once()
		mockOAuthService.On("GetUserInfo", mock.Anything, testToken).Return(testUser, nil).Once()

		// Prepare request
		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s&state=%s", testCode, testState)
		req := httptest.NewRequest("GET", targetURL, nil)
		// Add the state cookie to the request
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assertions
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check if state cookie was cleared (Set-Cookie with past expiry)
		foundClearCookie := false
		for _, c := range resp.Cookies() {
			if c.Name == cfg.StateCookieName && c.Expires.Before(time.Now()) {
				foundClearCookie = true
				break
			}
		}
		assert.True(t, foundClearCookie, "State cookie should be cleared")

		// Check response body
		var respBody map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)
		assert.Equal(t, "Login successful!", respBody["message"])

		// Check nested user data (requires converting map[string]interface{} back)
		userData, ok := respBody["user"].(map[string]interface{})
		require.True(t, ok, "User data is not a map")
		assert.Equal(t, testUser.ID, userData["id"])
		assert.Equal(t, testUser.DisplayName, userData["displayName"])
		assert.Equal(t, testUser.Email, userData["mail"]) // Matches the json tag in models.OAuthUser

		mockOAuthService.AssertExpectations(t)
	})

	t.Run("StateMismatch", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		wrongState := uuid.NewString()
		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s&state=%s", testCode, wrongState)
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState, // Cookie has the correct state
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "Invalid state parameter")

		// Check if state cookie was cleared even on error
		foundClearCookie := false
		for _, c := range resp.Cookies() {
			if c.Name == cfg.StateCookieName && c.Expires.Before(time.Now()) {
				foundClearCookie = true
				break
			}
		}
		assert.True(t, foundClearCookie, "State cookie should be cleared even on state mismatch error")

		mockOAuthService.AssertNotCalled(t, "ExchangeCode", mock.Anything, mock.Anything)
		mockOAuthService.AssertNotCalled(t, "GetUserInfo", mock.Anything, mock.Anything)
	})

	t.Run("MissingStateQueryParam", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s", testCode) // No state
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "State parameter missing")

		// Check if state cookie was cleared
		foundClearCookie := false
		for _, c := range resp.Cookies() {
			if c.Name == cfg.StateCookieName && c.Expires.Before(time.Now()) {
				foundClearCookie = true
				break
			}
		}
		assert.True(t, foundClearCookie, "State cookie should be cleared even on missing state param error")

		mockOAuthService.AssertNotCalled(t, "ExchangeCode", mock.Anything, mock.Anything)
	})

	t.Run("MissingStateCookie", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s&state=%s", testCode, testState)
		req := httptest.NewRequest("GET", targetURL, nil) // No cookie added

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "State cookie missing")

		// Check if state cookie was attempted to be cleared (it should be)
		foundClearCookie := false
		for _, c := range resp.Cookies() {
			if c.Name == cfg.StateCookieName && c.Expires.Before(time.Now()) {
				foundClearCookie = true
				break
			}
		}
		assert.True(t, foundClearCookie, "State cookie should be attempted to be cleared even if missing")

		mockOAuthService.AssertNotCalled(t, "ExchangeCode", mock.Anything, mock.Anything)
	})

	t.Run("MissingCode", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?state=%s", testState) // No code
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "Authorization code missing")

		mockOAuthService.AssertNotCalled(t, "ExchangeCode", mock.Anything, mock.Anything)
	})

	t.Run("CodeExchangeError", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		exchangeErr := errors.New("failed to exchange code")
		mockOAuthService.On("ExchangeCode", mock.Anything, testCode).Return(nil, exchangeErr).Once()

		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s&state=%s", testCode, testState)
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "Failed to exchange authorization code")

		mockOAuthService.AssertExpectations(t)
		mockOAuthService.AssertNotCalled(t, "GetUserInfo", mock.Anything, mock.Anything)
	})

	t.Run("GetUserInfoError", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		userInfoErr := errors.New("failed to fetch user info")
		mockOAuthService.On("ExchangeCode", mock.Anything, testCode).Return(testToken, nil).Once()
		mockOAuthService.On("GetUserInfo", mock.Anything, testToken).Return(nil, userInfoErr).Once()

		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?code=%s&state=%s", testCode, testState)
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "Failed to fetch user information")

		mockOAuthService.AssertExpectations(t)
	})

	t.Run("OAuthProviderErrorInCallback", func(t *testing.T) {
		// Reset mocks for subtest
		mockOAuthService := new(mocks.MockOAuthService)
		app := setupOAuthTestApp(mockOAuthService, cfg)

		oauthError := "access_denied"
		oauthErrorDesc := "The user denied access to the application."
		targetURL := fmt.Sprintf("/api/auth/oauth/microsoft/callback?error=%s&error_description=%s&state=%s", oauthError, url.QueryEscape(oauthErrorDesc), testState)
		req := httptest.NewRequest("GET", targetURL, nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.StateCookieName,
			Value: testState,
		})

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(bodyBytes), "Authorization code missing or error occurred during login: "+oauthErrorDesc)

		mockOAuthService.AssertNotCalled(t, "ExchangeCode", mock.Anything, mock.Anything)
	})
}
