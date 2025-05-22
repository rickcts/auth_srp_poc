package handlers

import (
	"errors" // Added errors
	"net/http"

	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
	"github.com/rickcts/srp/internal/service"

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
