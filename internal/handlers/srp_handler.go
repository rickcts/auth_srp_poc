package handlers

import (
	"errors" // Added errors
	"net/http"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"

	"github.com/gofiber/fiber/v2"
)

// SRPAuthHandler handles authentication-related HTTP requests
type SRPAuthHandler struct {
	SRPAuthService service.SRPAuthGenerator
}

// NewSRPAuthHandler creates a new AuthHandler
func NewSRPAuthHandler(authService service.SRPAuthGenerator) *SRPAuthHandler {
	return &SRPAuthHandler{SRPAuthService: authService}
}

// Register handles user registration requests
func (h *SRPAuthHandler) Register(c *fiber.Ctx) error {
	req := new(models.SRPRegisterRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	err := h.SRPAuthService.Register(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			return c.Status(http.StatusConflict).JSON(models.ErrorResponse{Error: "Username already exists"})
		}
		// Log the internal error details here in a real app
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Registration failed"})
	}

	return c.SendStatus(http.StatusCreated)
}

// AuthStep1 handles the first step of the SRP authentication flow
func (h *SRPAuthHandler) AuthStep1(c *fiber.Ctx) error {
	req := new(models.AuthStep1Request)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	resp, err := h.SRPAuthService.ComputeB(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return c.Status(http.StatusNotFound).JSON(models.ErrorResponse{Error: "User not found"})
		}
		// Log internal error details
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Authentication initiation failed"})
	}

	return c.Status(http.StatusOK).JSON(resp)
}

// AuthStep2 handles the verification of the client's proof M1
func (h *SRPAuthHandler) AuthStep2(c *fiber.Ctx) error {
	req := new(models.AuthStep2Request) // Client sends M1 in this step
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	resp, err := h.SRPAuthService.VerifyClientProof(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrStateNotFound) {
			return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Authentication session expired or invalid"})
		}
		if err.Error() == "client proof M1 verification failed" { // Check specific error string from service
			return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{Error: "Invalid client credentials"})
		}
		// Log internal error details
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Authentication verification failed"})
	}

	// Authentication successful! Return M2 and token
	return c.Status(http.StatusOK).JSON(resp)
}

func (h *SRPAuthHandler) ChangePassword(c *fiber.Ctx) error {
	authID, ok := c.Locals("authID").(string)
	if !ok || authID == "" {
		return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{Error: "User not authenticated"})
	}

	req := new(models.ChangePasswordRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()
	err := h.SRPAuthService.ChangePassword(ctx, authID, *req)
	if err != nil {

		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Failed to change password"})
	}
	return c.SendStatus(http.StatusOK)
}

// InitiatePasswordReset handles requests to start the password reset process.
func (h *SRPAuthHandler) InitiatePasswordReset(c *fiber.Ctx) error {
	req := new(models.InitiatePasswordResetRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()
	err := h.SRPAuthService.InitiatePasswordReset(ctx, *req)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{Error: "Password reset initiation failed"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "If your account exists, a password reset email has been sent."})
}

// CompletePasswordReset handles requests to complete the password reset process.
func (h *SRPAuthHandler) CompletePasswordReset(c *fiber.Ctx) error {
	req := new(models.CompletePasswordResetRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}
	ctx := c.UserContext()
	err := h.SRPAuthService.CompletePasswordReset(ctx, *req)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Password has been reset successfully."})
}
