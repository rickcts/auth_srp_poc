package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/service"
)

// OAuthHandler handles authentication-related HTTP requests
type OAuthHandler struct {
	OAuthService service.OAuthProvider
	Config       *config.Config
}

// NewOAuthHandler creates a new instance of AuthHandler
func NewOAuthHandler(oauthService service.OAuthProvider, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{
		OAuthService: oauthService,
		Config:       cfg,
	}
}

// Login initiates the OAuth2 flow by redirecting the user to Microsoft
func (h *OAuthHandler) Login(c *fiber.Ctx) error {
	state := uuid.NewString() // Generate random state for CSRF protection

	// Store state in a short-lived, secure cookie
	c.Cookie(&fiber.Cookie{
		Name:     h.Config.StateCookieName,
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute), // Short expiry
		HTTPOnly: true,                             // Prevent client-side script access
		Secure:   c.Secure(),                       // Set Secure flag if using HTTPS (recommended for production)
		SameSite: "Lax",                            // Lax is usually sufficient for OAuth redirects
	})

	authURL := h.OAuthService.GetAuthCodeURL(state)
	log.Printf("Redirecting user to: %s\n", authURL)

	// Use Temporary Redirect (307)
	return c.Redirect(authURL, http.StatusTemporaryRedirect)
}

// Callback handles the redirect back from Microsoft after authentication
func (h *OAuthHandler) Callback(c *fiber.Ctx) error {
	// --- State Verification (CSRF Protection) ---
	queryState := c.Query("state")
	cookieState := c.Cookies(h.Config.StateCookieName)

	// Clear the state cookie immediately after reading
	c.Cookie(&fiber.Cookie{
		Name:     h.Config.StateCookieName,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour), // Expire immediately
		HTTPOnly: true,
		Secure:   c.Secure(),
		SameSite: "Lax",
	})

	if queryState == "" {
		log.Println("Callback error: state parameter missing in callback URL")
		return c.Status(fiber.StatusBadRequest).SendString("State parameter missing")
	}
	if cookieState == "" {
		log.Println("Callback error: state cookie missing")
		return c.Status(fiber.StatusBadRequest).SendString("State cookie missing or expired")
	}
	if queryState != cookieState {
		log.Printf("Callback error: state mismatch. Query='%s', Cookie='%s'\n", queryState, cookieState)
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid state parameter")
	}
	log.Println("State verification successful")

	code := c.Query("code")
	if code == "" {
		errorMsg := c.Query("error")
		errorDesc := c.Query("error_description")
		log.Printf("Callback error: authorization code missing. Error: %s, Description: %s\n", errorMsg, errorDesc)
		return c.Status(fiber.StatusBadRequest).SendString("Authorization code missing or error occurred during login: " + errorDesc)
	}
	log.Println("Authorization code received")

	token, err := h.OAuthService.ExchangeCode(c.Context(), code) // Use request context
	if err != nil {
		log.Printf("Error exchanging code in callback: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange authorization code for token")
	}
	log.Println("Token exchange successful")

	// --- Fetch User Info ---
	user, err := h.OAuthService.GetUserInfo(c.Context(), token) // Use request context
	if err != nil {
		log.Printf("Error fetching user info in callback: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to fetch user information")
	}
	log.Printf("Successfully logged in user: %s (%s)\n", user.DisplayName, user.Email)

	// For this example, just return the user info as JSON
	return c.JSON(fiber.Map{
		"message": "Login successful!",
		"user":    user,
		// "access_token": token.AccessToken,
	})
}
