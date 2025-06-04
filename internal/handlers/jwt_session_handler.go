package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type JWTAuthHandler struct {
	JWTAuthService service.JWTGenerator
	SessionService service.SessionGenerator
}

// NewJWTAuthHandler creates a new AuthHandler
func NewJWTAuthHandler(authService service.JWTGenerator, sessionService service.SessionGenerator) *JWTAuthHandler {
	return &JWTAuthHandler{
		JWTAuthService: authService,
		SessionService: sessionService,
	}
}

// VerifyToken verifies jwt token and check if it is currently valid session token
func (h *JWTAuthHandler) VerifyToken(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
	}

	sessionTokenID := parts[1]

	log.Printf("[JWTAuthHandler.VerifyToken] Attempting to verify session token: %.10s...", sessionTokenID)

	ctx := c.Request().Context()

	resp, err := h.SessionService.VerifySessionToken(ctx, sessionTokenID)
	if err != nil {
		log.Printf("[JWTAuthHandler.VerifyToken] Session verification failed for token %.10s...: %v", sessionTokenID, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired session token")
	}

	if !resp.IsValid {
		log.Printf("[JWTAuthHandler.VerifyToken] Session token %.10s... is explicitly marked as invalid.", sessionTokenID)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session token")
	}

	return c.NoContent(http.StatusOK)
}

// Logout current session by delete sessionID in the session store
func (h *JWTAuthHandler) Logout(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is missing")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
	}
	sessionTokenID := parts[1]

	if sessionTokenID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Session token is required for logout")
	}

	err := h.SessionService.SignOut(c.Request().Context(), sessionTokenID)
	if err != nil {
		log.Printf("[JWTAuthHandler.Logout] Logout failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process logout")
	}

	log.Printf("[JWTAuthHandler.Logout] User successfully logged out for session token (prefix): %.10s...", sessionTokenID)
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out"})
}

// LogoutAllDevices handles logging out the user for all logged in sessions.
func (h *JWTAuthHandler) LogoutAllSessions(c echo.Context) error {
	userContext := c.Get("user")
	if userContext == nil {
		log.Printf("[JWTAuthHandler.LogoutAllDevices] Error: 'user' not found in context. This indicates a middleware issue or misconfiguration.")
		// This case should ideally be caught by middleware, returning 401.
		// If it reaches here, it's an unexpected state.
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated: context missing user information")
	}

	user, ok := userContext.(*jwt.Token)
	if !ok {
		log.Printf("[JWTAuthHandler.LogoutAllDevices] Error: 'user' in context is not of type *jwt.Token. Actual type: %T", userContext)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error: user context type mismatch")
	}

	authID, err := user.Claims.GetSubject()
	if err != nil {
		log.Printf("[JWTAuthHandler.LogoutAllDevices] Error getting subject claim from token: %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: cannot get subject")
	} else if authID == "" {
		log.Printf("[JWTAuthHandler.LogoutAllDevices] Error: Subject claim is empty in token.")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: subject claim is missing or empty")
	}

	authHeader := c.Request().Header.Get("Authorization") // This header is for the *current* session token to exclude.
	var sessionTokenID string
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			sessionTokenID = parts[1]
		} else {
			// Invalid format, but we can proceed without an exclusion token.
			// Or, you could return an error if a valid Bearer token for exclusion is strictly required.
			// For now, let's assume it's optional for exclusion.
			log.Printf("[JWTAuthHandler.LogoutAllDevices] Warning: Authorization header present but format is not 'Bearer {token}'. Proceeding without excluding current token.")
		}
	}

	var excludeTokens []string
	if sessionTokenID != "" {
		excludeTokens = append(excludeTokens, sessionTokenID)
	}

	deletedCount, err := h.SessionService.SignOutUserSessions(c.Request().Context(), authID, excludeTokens...)
	if err != nil {
		log.Printf("[JWTAuthHandler.LogoutAllDevices] Failed to logout all devices for AuthID %v: %v", authID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to logout other devices")
	}

	log.Printf("[JWTAuthHandler.LogoutAllDevices] Successfully logged out %d other devices for AuthID %v", deletedCount, authID)
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out other devices.", "devices_logged_out": deletedCount})
}
