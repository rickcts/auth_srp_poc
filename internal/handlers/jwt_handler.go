package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
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

func (h *JWTAuthHandler) VerifyToken(c echo.Context) error {
	authHeader := c.Get("Authorization").(string)
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
		// Return 401 if the session is not found or expired
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired session token")
	}

	if !resp.IsValid {
		log.Printf("[JWTAuthHandler.VerifyToken] Session token %.10s... is explicitly marked as invalid.", sessionTokenID)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session token")
	}

	return c.NoContent(http.StatusOK) // Explicitly return 200 OK or 204 No Content
}

func (h *JWTAuthHandler) Logout(c echo.Context) error {
	// Logout invalidates the current session token.
	// The token should be passed in the Authorization header.
	authHeader := c.Get("Authorization").(string)
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
		log.Printf("[SRPAuthHandler.Logout] Logout failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process logout")
	}

	log.Printf("[SRPAuthHandler.Logout] User successfully logged out for session token (prefix): %.10s...", sessionTokenID)
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out"})
}

// LogoutAllDevices handles logging out the user from all other devices.
func (h *JWTAuthHandler) LogoutAllDevices(c echo.Context) error {
	// This handler assumes AuthMiddleware has run and placed userID and current sessionTokenID in c.Locals
	userId, okUserId := c.Get("userId").(int64)
	currentSessionTokenID, okCurrentToken := c.Get("sessionTokenID").(string)

	if !okUserId || userId <= 0 {
		log.Printf("[SRPAuthHandler.LogoutAllDevices] UserID not found in context. AuthMiddleware might not have run or failed.")
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}

	var excludeTokens []string
	if okCurrentToken && currentSessionTokenID != "" {
		excludeTokens = append(excludeTokens, currentSessionTokenID)
	}

	deletedCount, err := h.SessionService.SignOutUserSessions(c.Request().Context(), userId, excludeTokens...)
	if err != nil {
		log.Printf("[SRPAuthHandler.LogoutAllDevices] Failed to logout other devices for UserID %v: %v", userId, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to logout other devices")
	}

	log.Printf("[SRPAuthHandler.LogoutAllDevices] Successfully logged out %d other devices for UserID %v", deletedCount, userId)
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out other devices.", "devices_logged_out": deletedCount})
}
