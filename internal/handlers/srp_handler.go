package handlers

import (
	"errors" // Added errors
	"net/http"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"

	"github.com/labstack/echo/v4"
)

// SRPAuthHandler handles authentication-related HTTP requests
type SRPAuthHandler struct {
	SRPAuthService service.SRPAuthGenerator
}

// NewSRPAuthHandler creates a new AuthHandler
func NewSRPAuthHandler(authService service.SRPAuthGenerator) *SRPAuthHandler {
	return &SRPAuthHandler{SRPAuthService: authService}
}

// CheckEmailExists checks if the user email is already in the database
func (h *SRPAuthHandler) CheckEmailExists(c echo.Context) error {
	req := new(models.AuthIDRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()

	isUserExists, err := h.SRPAuthService.CheckIfUserExists(ctx, *req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	return c.JSON(http.StatusOK, echo.Map{"exists": isUserExists})
}

// Register handles user registration requests
func (h *SRPAuthHandler) Register(c echo.Context) error {
	req := new(models.SRPRegisterRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()

	err := h.SRPAuthService.Register(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			return echo.NewHTTPError(http.StatusConflict, "Username already exists")
		}
		// Log the internal error details here in a real app
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	return c.NoContent(http.StatusCreated)
}

// AuthStep1 handles the first step of the SRP authentication flow
func (h *SRPAuthHandler) AuthStep1(c echo.Context) error {
	req := new(models.AuthStep1Request)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()

	resp, err := h.SRPAuthService.ComputeB(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		// Log internal error details
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication initiation failed")
	}

	return c.JSON(http.StatusOK, resp)
}

// AuthStep2 handles the verification of the client's proof M1
func (h *SRPAuthHandler) AuthStep2(c echo.Context) error {
	req := new(models.AuthStep2Request) // Client sends M1 in this step
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()

	resp, err := h.SRPAuthService.VerifyClientProof(ctx, *req)
	if err != nil {
		if errors.Is(err, repository.ErrStateNotFound) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Authentication session expired or invalid")
		}
		if err.Error() == "client proof M1 verification failed" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid client credentials")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication verification failed")
	}

	// Authentication successful! Return M2 and token
	return c.JSON(http.StatusOK, resp)
}

func (h *SRPAuthHandler) ChangePassword(c echo.Context) error {
	authID, ok := c.Get("authID").(string) // Use c.Get for values from context (e.g., middleware)
	if !ok || authID == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}

	req := new(models.ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()
	err := h.SRPAuthService.ChangePassword(ctx, authID, *req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to change password")
	}
	return c.NoContent(http.StatusOK)
}

// InitiatePasswordReset handles requests to start the password reset process.
func (h *SRPAuthHandler) InitiatePasswordReset(c echo.Context) error {
	req := new(models.InitiatePasswordResetRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()
	err := h.SRPAuthService.InitiatePasswordReset(ctx, *req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Password reset initiation failed")
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "If your account exists, a password reset email has been sent."})
}

// CompletePasswordReset handles requests to complete the password reset process.
func (h *SRPAuthHandler) CompletePasswordReset(c echo.Context) error {
	req := new(models.CompletePasswordResetRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}
	ctx := c.Request().Context()
	err := h.SRPAuthService.CompletePasswordReset(ctx, *req)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "Password has been reset successfully."})
}
