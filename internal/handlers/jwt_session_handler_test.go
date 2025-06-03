package handlers_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/mocks"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type jwtAuthHandlerTestDeps struct {
	mockJWTAuthService *mocks.MockJWTGenerator     // Renamed for clarity
	mockSessionService *mocks.MockSessionGenerator // Renamed for clarity
	handler            *handlers.JWTAuthHandler
	echo               *echo.Echo
}

func setupJWTAuthHandlerTest(t *testing.T) jwtAuthHandlerTestDeps {
	t.Helper()
	deps := jwtAuthHandlerTestDeps{
		mockJWTAuthService: new(mocks.MockJWTGenerator),
		mockSessionService: new(mocks.MockSessionGenerator),
	}
	deps.handler = handlers.NewJWTAuthHandler(deps.mockJWTAuthService, deps.mockSessionService)
	deps.echo = echo.New()
	// Register routes directly for testing individual handlers
	// This avoids needing the full router setup with actual middleware for unit tests
	deps.echo.POST("/verify", deps.handler.VerifyToken)
	deps.echo.GET("/logout", deps.handler.Logout) // Assuming GET based on router, adjust if POST
	deps.echo.POST("/logout-all", deps.handler.LogoutAllDevices)
	return deps
}

func performJWTRequest(e *echo.Echo, method, path, token string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestJWTAuthHandler_VerifyToken(t *testing.T) {
	validToken := "valid-session-token"

	t.Run("Success", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deps.mockSessionService.On("VerifySessionToken", mock.Anything, validToken).
			Return(&models.VerifyTokenResponse{IsValid: true, UserID: 1, SessionID: validToken}, nil).Once()

		rec := performJWTRequest(deps.echo, http.MethodPost, "/verify", validToken, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("MissingAuthHeader", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		rec := performJWTRequest(deps.echo, http.MethodPost, "/verify", "", nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Authorization header is missing", errResp.Message)
		deps.mockSessionService.AssertNotCalled(t, "VerifySessionToken", mock.Anything, mock.Anything)
	})

	t.Run("InvalidAuthHeaderFormat", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", "InvalidTokenFormat")
		rec := httptest.NewRecorder()
		deps.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Authorization header format must be Bearer {token}", errResp.Message)
	})

	t.Run("SessionServiceError", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		serviceErr := errors.New("session store unavailable")
		deps.mockSessionService.On("VerifySessionToken", mock.Anything, validToken).Return(nil, serviceErr).Once()

		rec := performJWTRequest(deps.echo, http.MethodPost, "/verify", validToken, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Invalid or expired session token", errResp.Message)
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("SessionNotValid", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deps.mockSessionService.On("VerifySessionToken", mock.Anything, validToken).
			Return(&models.VerifyTokenResponse{IsValid: false, UserID: 1, SessionID: validToken}, nil).Once()

		rec := performJWTRequest(deps.echo, http.MethodPost, "/verify", validToken, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Invalid session token", errResp.Message) // This specific message is from the handler
		deps.mockSessionService.AssertExpectations(t)
	})
}

func TestJWTAuthHandler_Logout(t *testing.T) {
	sessionToken := "session-to-logout"

	t.Run("Success", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deps.mockSessionService.On("SignOut", mock.Anything, sessionToken).Return(nil).Once()

		rec := performJWTRequest(deps.echo, http.MethodGet, "/logout", sessionToken, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		var respMap map[string]string
		err := json.Unmarshal(rec.Body.Bytes(), &respMap)
		require.NoError(t, err)
		assert.Equal(t, "Successfully logged out", respMap["message"])
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("MissingAuthHeader", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		rec := performJWTRequest(deps.echo, http.MethodGet, "/logout", "", nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		deps.mockSessionService.AssertNotCalled(t, "SignOut", mock.Anything, mock.Anything)
	})

	t.Run("InvalidAuthHeaderFormat", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		req.Header.Set("Authorization", "Invalid ") // Malformed
		rec := httptest.NewRecorder()
		deps.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Authorization header format must be Bearer {token}", errResp.Message)
	})

	t.Run("EmptyTokenInHeader", func(t *testing.T) {
		// This case is interesting because "Bearer " is valid format, but token is empty.
		// The handler's SignOut check for sessionTokenID == "" would catch this *after* parsing.
		// However, the current handler logic for SignOut doesn't explicitly return BadRequest for empty token *after* parsing,
		// it relies on the service. Let's test the current behavior.
		// If the token part is truly empty, `parts[1]` would be empty.
		// The `sessionTokenID == ""` check is before calling the service.
		deps := setupJWTAuthHandlerTest(t)

		// Manually create context and call handler to test the empty token string logic precisely
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		req.Header.Set("Authorization", "Bearer ") // Token part is empty
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := deps.handler.Logout(c) // Call handler directly

		require.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Equal(t, "Session token is required for logout", httpErr.Message)

		deps.mockSessionService.AssertNotCalled(t, "SignOut", mock.Anything, mock.Anything)
	})

	t.Run("SessionServiceError", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		serviceErr := errors.New("db error during signout")
		deps.mockSessionService.On("SignOut", mock.Anything, sessionToken).Return(serviceErr).Once()

		rec := performJWTRequest(deps.echo, http.MethodGet, "/logout", sessionToken, nil)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Failed to process logout", errResp.Message)
		deps.mockSessionService.AssertExpectations(t)
	})
}

func TestJWTAuthHandler_LogoutAllDevices(t *testing.T) {
	userID := int64(123)
	userIDStr := strconv.FormatInt(userID, 10)
	currentToken := "current-active-token"

	createTestToken := func(subject string) *jwt.Token {
		return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": subject})
	}

	performLogoutAllRequest := func(deps jwtAuthHandlerTestDeps, tokenToExclude string, userContextToken *jwt.Token) *httptest.ResponseRecorder {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
		if tokenToExclude != "" {
			req.Header.Set("Authorization", "Bearer "+tokenToExclude)
		}
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if userContextToken != nil {
			c.Set("user", userContextToken)
		}
		// Call handler directly as it depends on c.Get("user")
		err := deps.handler.LogoutAllDevices(c)
		if err != nil {
			// If handler returns error, echo might not have written to `rec` yet.
			// We need to send the error through echo's error handler to populate `rec`.
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}

	t.Run("Success", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deletedCount := int64(5)
		deps.mockSessionService.On("SignOutUserSessions", mock.Anything, userID, currentToken).
			Return(deletedCount, nil).Once()

		rec := performLogoutAllRequest(deps, currentToken, createTestToken(userIDStr))

		assert.Equal(t, http.StatusOK, rec.Code)
		var respMap map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &respMap)
		require.NoError(t, err)
		assert.Equal(t, "Successfully logged out other devices.", respMap["message"])
		// JSON numbers are often float64 when unmarshaled into interface{}
		assert.EqualValues(t, deletedCount, respMap["devices_logged_out"])
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("UserNotInContext", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		// No c.Set("user", ...)
		rec := performLogoutAllRequest(deps, currentToken, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		err := json.Unmarshal(rec.Body.Bytes(), &errResp)
		require.NoError(t, err)
		assert.Equal(t, "User not authenticated: context missing user information", errResp.Message)
		deps.mockSessionService.AssertNotCalled(t, "SignOutUserSessions", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("UserInContextWrongType", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
		req.Header.Set("Authorization", "Bearer "+currentToken)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", "this-is-not-a-jwt-token") // Set user to a wrong type

		err := deps.handler.LogoutAllDevices(c)
		if err != nil {
			e.HTTPErrorHandler(err, c)
		}

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Internal server error: user context type mismatch", errResp.Message)
	})

	t.Run("UserInContextButTokenClaimsBad", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		badToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"not_sub": "anything"}) // No "sub"
		rec := performLogoutAllRequest(deps, currentToken, badToken)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Invalid token: subject claim is missing or empty", errResp.Message)
	})

	t.Run("MissingAuthHeaderForExclusionButUserInContextIsValid", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deletedCount := int64(5)
		deps.mockSessionService.On("SignOutUserSessions", mock.Anything, userID). // No variadic args passed if excludeTokens is empty
												Return(deletedCount, nil).Once()

		// Simulate request where Auth header for exclusion is missing, but user is in context (from middleware)
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout-all", nil) // No Auth Header
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", createTestToken(userIDStr)) // "user" IS set by middleware

		err := deps.handler.LogoutAllDevices(c) // Call handler directly
		if err != nil {
			e.HTTPErrorHandler(err, c)
		}
		assert.Equal(t, http.StatusOK, rec.Code) // Should succeed, just won't exclude current token
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("MalformedAuthHeaderForExclusionButUserInContextIsValid", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deletedCount := int64(5)
		// Service will be called with an empty exclude list because the token part of "Bearer " is empty
		deps.mockSessionService.On("SignOutUserSessions", mock.Anything, userID). // No variadic args
												Return(deletedCount, nil).Once()

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
		req.Header.Set("Authorization", "InvalidFormat") // Malformed Auth Header for exclusion
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", createTestToken(userIDStr)) // "user" IS set by middleware

		err := deps.handler.LogoutAllDevices(c)
		if err != nil {
			e.HTTPErrorHandler(err, c)
		}
		assert.Equal(t, http.StatusOK, rec.Code) // Should succeed
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("InvalidUserIDString", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		rec := performLogoutAllRequest(deps, currentToken, createTestToken("not-an-int"))

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Failed to parse user identifier", errResp.Message)
		deps.mockSessionService.AssertNotCalled(t, "SignOutUserSessions", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("SessionServiceError", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		serviceErr := errors.New("db error during mass logout")
		deps.mockSessionService.On("SignOutUserSessions", mock.Anything, userID, currentToken).
			Return(int64(0), serviceErr).Once()

		rec := performLogoutAllRequest(deps, currentToken, createTestToken(userIDStr))

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp echo.HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		assert.Equal(t, "Failed to logout other devices", errResp.Message)
		deps.mockSessionService.AssertExpectations(t)
	})

	t.Run("SuccessNoCurrentTokenToExclude", func(t *testing.T) {
		deps := setupJWTAuthHandlerTest(t)
		deletedCount := int64(5)
		// This happens if Authorization header is present but token part is empty,
		// or if the logic decided excludeTokens should be empty.
		// The handler code: `if sessionTokenID != "" { excludeTokens = append(excludeTokens, sessionTokenID) }`
		// So if sessionTokenID (from header) is empty, excludeTokens is empty.
		deps.mockSessionService.On("SignOutUserSessions", mock.Anything, userID). // No variadic args
												Return(deletedCount, nil).Once()

		// Simulate request where "Authorization: Bearer " (empty token)
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
		req.Header.Set("Authorization", "Bearer ") // Empty token part
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", createTestToken(userIDStr))

		err := deps.handler.LogoutAllDevices(c)
		if err != nil {
			e.HTTPErrorHandler(err, c)
		}

		assert.Equal(t, http.StatusOK, rec.Code)
		var respMap map[string]interface{}
		err = json.Unmarshal(rec.Body.Bytes(), &respMap)
		require.NoError(t, err)
		assert.EqualValues(t, deletedCount, respMap["devices_logged_out"])
		deps.mockSessionService.AssertExpectations(t)
	})
}
