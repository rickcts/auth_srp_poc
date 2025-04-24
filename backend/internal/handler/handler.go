package handler

import (
	"errors" // Added errors
	"net/http"

	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
	"github.com/rickcts/srp/internal/service"

	"github.com/gofiber/fiber/v2"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService service.AuthGenerator
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService service.AuthGenerator) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles user registration requests
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	req := new(models.RegisterRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	err := h.authService.Register(ctx, *req)
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
func (h *AuthHandler) AuthStep1(c *fiber.Ctx) error {
	req := new(models.AuthStep1Request)
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	resp, err := h.authService.ComputeB(ctx, *req)
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
func (h *AuthHandler) AuthStep2(c *fiber.Ctx) error {
	req := new(models.AuthStep2Request) // Client sends M1 in this step
	if err := c.BodyParser(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{Error: "Invalid request body"})
	}

	ctx := c.UserContext()

	resp, err := h.authService.VerifyClientProof(ctx, *req)
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
