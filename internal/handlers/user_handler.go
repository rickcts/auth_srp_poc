package handlers

import (
	"net/http"
	"strings"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

type UserHandler struct {
	JWTService     service.JWTGenerator
	SessionService service.SessionGenerator
	UserSerivice   service.UserGenerator
}

// NewUserHandler creates a new AuthHandler
func NewUserHandler(authService service.JWTGenerator, sessionService service.SessionGenerator, userService service.UserGenerator) *UserHandler {
	return &UserHandler{
		JWTService:     authService,
		SessionService: sessionService,
		UserSerivice:   userService,
	}
}

// VerifyToken verifies jwt token and check if it is currently valid session token
func (h *UserHandler) VerifyToken(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
	}

	sessionTokenID := parts[1]

	log.Debug().Str("tokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Attempting to verify session token")

	ctx := c.Request().Context()

	resp, err := h.SessionService.VerifySessionToken(ctx, sessionTokenID)
	if err != nil {
		log.Warn().Err(err).Str("tokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Session verification failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired session token")
	}

	if !resp.IsValid {
		log.Warn().Str("tokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Session token is explicitly marked as invalid")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session token")
	}

	return c.NoContent(http.StatusOK)
}

func (h *UserHandler) GetUserSessions(c echo.Context) error {
	userContext := c.Get("user")
	if userContext == nil {
		// This case should ideally be caught by middleware, returning 401.
		// If it reaches here, it's an unexpected state.
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated: context missing user information")
	}

	user, ok := userContext.(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error: user context type mismatch")
	}

	authID, err := user.Claims.GetSubject()
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: cannot get subject")
	} else if authID == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: subject claim is missing or empty")
	}

	resp, err := h.SessionService.GetUserSessions(c.Request().Context(), authID)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to get user sessions")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user sessions")
	}

	return c.JSON(http.StatusOK, resp)
}

// Logout current session by delete sessionID in the session store
func (h *UserHandler) Logout(c echo.Context) error {
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
		log.Error().Err(err).Str("tokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Logout failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process logout")
	}

	log.Info().Str("tokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("User successfully logged out")
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out"})
}

// Get authID from jwt, return http error not able to parse
func getAuthIDFromContext(c echo.Context) (string, error) {
	userContext := c.Get("user")
	if userContext == nil {
		log.Error().Msg("'user' not found in context. This indicates a middleware issue or misconfiguration.")
		// This case should ideally be caught by middleware, returning 401.
		// If it reaches here, it's an unexpected state.
		return "", echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated: context missing user information")
	}

	user, ok := userContext.(*jwt.Token)
	if !ok {
		log.Error().Interface("actualType", userContext).Msg("'user' in context is not of type *jwt.Token")
		return "", echo.NewHTTPError(http.StatusInternalServerError, "Internal server error: user context type mismatch")
	}

	authID, err := user.Claims.GetSubject()
	if err != nil {
		log.Error().Err(err).Msg("Error getting subject claim from token")
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: cannot get subject")
	} else if authID == "" {
		log.Error().Msg("Subject claim is empty in token")
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: subject claim is missing or empty")
	}
	return authID, nil
}

// LogoutAllDevices handles logging out the user for all logged in sessions.
func (h *UserHandler) LogoutAllSessions(c echo.Context) error {
	authID, err := getAuthIDFromContext(c)
	if err != nil {
		return err
	}

	authHeader := c.Request().Header.Get("Authorization") // This header is for the *current* session token to exclude.
	var currentSessionTokenID string
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			currentSessionTokenID = parts[1]
		} else {
			// Invalid format, but we can proceed without an exclusion token.
			// Or, you could return an error if a valid Bearer token for exclusion is strictly required.
			// For now, let's assume it's optional for exclusion.
			log.Warn().Str("authHeader", authHeader).Msg("Authorization header present but format is not 'Bearer {token}'. Proceeding without excluding current token for LogoutAllSessions.")
		}
	}

	var excludeTokens []string
	if currentSessionTokenID != "" {
		ctx := c.Request().Context()
		resp, err := h.SessionService.VerifySessionToken(ctx, currentSessionTokenID)
		if err != nil {
			log.Warn().Err(err).Str("tokenPrefix", безопасныйПрефикс(currentSessionTokenID, 10)).Msg("Session verification failed for exclusion token during LogoutAllSessions")
			// If the token meant for exclusion is invalid, it's safer to return an error
			// than to proceed and potentially not exclude an active (but unverified) session.
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired session token provided for exclusion")
		}

		if !resp.IsValid {
			log.Warn().Str("tokenPrefix", безопасныйПрефикс(currentSessionTokenID, 10)).Msg("Session token for exclusion is explicitly marked as invalid during LogoutAllSessions")
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session token provided for exclusion")
		}
		// Only add to excludeTokens if it's valid and non-empty
		excludeTokens = append(excludeTokens, currentSessionTokenID)
	}

	deletedCount, err := h.SessionService.SignOutUserSessions(c.Request().Context(), authID, excludeTokens...)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to logout all devices")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to logout other devices")
	}

	log.Info().Int64("deletedCount", deletedCount).Str("authId", authID).Msg("Successfully logged out other devices")
	return c.JSON(http.StatusOK, echo.Map{"message": "Successfully logged out other devices.", "devices_logged_out": deletedCount})
}

func (h *UserHandler) UpdateUser(c echo.Context) error {
	authID, err := getAuthIDFromContext(c)
	if err != nil {
		return err
	}

	req := new(models.NewUserInfoRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	err = h.UserSerivice.UpdateUserInfo(c.Request().Context(), authID, req.DisplayName)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to update user info")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update user info")
	}

	return c.NoContent(http.StatusResetContent)
}

func (h *UserHandler) DeleteUser(c echo.Context) error {
	authID, err := getAuthIDFromContext(c)
	if err != nil {
		return err
	}
	err = h.UserSerivice.DeleteUser(c.Request().Context(), authID)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to delete user")
		// Consider what status code to return. If user not found is a possible error, maybe 404.
		// For now, a generic 500 if any error occurs.
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user")
	}
	return c.NoContent(http.StatusNoContent)
}

func безопасныйПрефикс(s string, length int) string {
	if len(s) > length {
		return s[:length]
	}
	return s
}
