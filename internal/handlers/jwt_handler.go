package handlers

import (
	"log"
	"strings"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/gofiber/fiber/v2"
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

func (h *JWTAuthHandler) VerifyToken(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Authorization header is missing"})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Authorization header format must be Bearer {token}"})
	}

	sessionTokenID := parts[1]

	log.Printf("[JWTAuthHandler.VerifyToken] Attempting to verify session token: %.10s...", sessionTokenID)

	ctx := c.UserContext()

	resp, err := h.SessionService.VerifySessionToken(ctx, sessionTokenID)
	if err != nil {
		log.Printf("[JWTAuthHandler.VerifyToken] Session verification failed for token %.10s...: %v", sessionTokenID, err)
		// Return 401 if the session is not found or expired
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Invalid or expired session token"})
	}

	if !resp.IsValid {
		log.Printf("[JWTAuthHandler.VerifyToken] Session token %.10s... is explicitly marked as invalid.", sessionTokenID)
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Invalid session token"})

	}

	return nil
}

func (h *JWTAuthHandler) Logout(c *fiber.Ctx) error {
	// Logout invalidates the current session token.
	// The token should be passed in the Authorization header.
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Authorization header is missing"})
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Authorization header format must be Bearer {token}"})
	}
	sessionTokenID := parts[1]

	if sessionTokenID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{Error: "Session token is required for logout"})
	}

	err := h.SessionService.SignOut(c.Context(), sessionTokenID)
	if err != nil {
		log.Printf("[SRPAuthHandler.Logout] Logout failed: %v", err)
		// Even if the token is not found, it's effectively logged out.
		// You might want to return 200 OK unless there's a server error.
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Failed to process logout"})
	}

	log.Printf("[SRPAuthHandler.Logout] User successfully logged out for session token (prefix): %.10s...", sessionTokenID)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully logged out"})
}

// LogoutAllDevices handles logging out the user from all other devices.
func (h *JWTAuthHandler) LogoutAllDevices(c *fiber.Ctx) error {
	// This handler assumes AuthMiddleware has run and placed userID and current sessionTokenID in c.Locals
	userId, okUserId := c.Locals("userId").(int64)
	currentSessionTokenID, okCurrentToken := c.Locals("sessionTokenID").(string)

	if !okUserId || userId <= 0 {
		log.Printf("[SRPAuthHandler.LogoutAllDevices] UserID not found in context. AuthMiddleware might not have run or failed.")
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{Error: "User not authenticated"})
	}

	var excludeTokens []string
	if okCurrentToken && currentSessionTokenID != "" {
		excludeTokens = append(excludeTokens, currentSessionTokenID)
	}

	deletedCount, err := h.SessionService.SignOutUserSessions(c.Context(), userId, excludeTokens...)
	if err != nil {
		log.Printf("[SRPAuthHandler.LogoutAllDevices] Failed to logout other devices for UserID %v: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Failed to logout other devices"})
	}

	log.Printf("[SRPAuthHandler.LogoutAllDevices] Successfully logged out %d other devices for UserID %v", deletedCount, userId)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully logged out other devices.", "devices_logged_out": deletedCount})
}
