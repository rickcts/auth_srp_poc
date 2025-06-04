package handlers

import (
	"errors" // Added errors
	"net/http"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/golang-jwt/jwt/v5"

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

// ValidatePasswordResetToken handles requests to validate a password reset token.
func (h *SRPAuthHandler) ValidatePasswordResetToken(c echo.Context) error {
	bindReq := new(models.ValidatePasswordResetTokenRequest)
	if err := c.Bind(bindReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	if bindReq.Token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token cannot be empty")
	}

	ctx := c.Request().Context()
	resp, err := h.SRPAuthService.ValidatePasswordResetToken(ctx, *bindReq)

	if err != nil {
		// If err is not nil, it means validation failed or an unexpected error occurred.
		// The service method ValidatePasswordResetToken ensures `resp` is non-nil
		// with `IsValid: false` for token validation failures (e.g., token not found/expired).
		if resp != nil && !resp.IsValid {
			// Return 200 OK with the response body indicating IsValid: false.
			// The client should check the IsValid field.
			return c.JSON(http.StatusOK, resp)
		}
		// For other errors (e.g., service's own pre-check failures or unexpected issues where resp might be nil)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Success: err is nil, resp is non-nil with IsValid: true
	return c.JSON(http.StatusOK, resp)
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

// InitiatePasswordChangeVerification handles the first step for an authenticated user to change their password.
// It requires JWT authentication.
func (h *SRPAuthHandler) InitiatePasswordChangeVerification(c echo.Context) error {
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

	ctx := c.Request().Context()
	resp, err := h.SRPAuthService.InitiatePasswordChangeVerification(ctx, authID)
	if err != nil {
		// Log internal error details
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to initiate password change verification")
	}
	return c.JSON(http.StatusOK, resp)
}

// ConfirmPasswordChange handles the second step for an authenticated user to change their password.
// It requires JWT authentication.
func (h *SRPAuthHandler) ConfirmPasswordChange(c echo.Context) error {
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

	req := new(models.ConfirmChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Request().Context()
	err = h.SRPAuthService.ConfirmPasswordChange(ctx, authID, *req)
	if err != nil {
		if errors.Is(err, service.ErrSRPAuthenticationFailed) || errors.Is(err, repository.ErrStateNotFound) {
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error()) // "current password verification failed" or "session expired"
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to confirm password change")
	}
	return c.NoContent(http.StatusOK) // Or http.StatusOk with a success message
}
