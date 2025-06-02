package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	state := uuid.NewString()

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

	return c.Redirect(authURL, http.StatusTemporaryRedirect)
}

// Callback handles the web redirect back from Microsoft after authentication
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
	user, err := h.OAuthService.ProcessUserInfo(c.Context(), token, "MICROSOFT") // Use request context
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

// MobileLogin handles the token exchange initiated by a mobile application.
func (h *OAuthHandler) MobileLogin(c *fiber.Ctx) error {
	var req models.MobileLoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("MobileLogin error: Failed to parse request body: %v\n", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Code == "" || req.CodeVerifier == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing code or code_verifier",
		})
	}
	log.Printf("MobileLogin: Received code and verifier.")

	oauth2token, err := h.OAuthService.ExchangeCodeMobile(c.Context(), req.Code, req.CodeVerifier, req.AuthProvider)
	if err != nil {
		log.Printf("MobileLogin error: Failed to exchange code: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to authenticate with provider",
		})
	}
	log.Println("MobileLogin: Token exchange successful.")

	user, err := h.OAuthService.ProcessUserInfo(c.Context(), oauth2token, req.AuthProvider)
	// user, err := h.OAuthService.ProcessUserInfo(c.Context(), oauth2token, req.AuthProvider)
	if err != nil {
		log.Printf("MobileLogin error: Failed to fetch user info: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user information",
		})
	}
	log.Printf("MobileLogin: Successfully logged in user: %s (%s)\n", user.DisplayName, user.Email)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Login successful!",
		"user":    user,
	})
}

func (h *OAuthHandler) GetUserInfoHandler(c *fiber.Ctx) error {
	accessToken, ok := c.Locals("accessToken").(string)
	if !ok || accessToken == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Access token not found in context",
		})
	}

	req, err := http.NewRequest("GET", "https://graph.microsoft.com/oidc/userinfo", nil)
	if err != nil {
		log.Printf("Error creating UserInfo request: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not create request to userinfo endpoint",
		})
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error calling UserInfo endpoint: %v", err)
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Failed to call userinfo endpoint",
		})
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorBody map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&errorBody); err == nil {
			log.Printf("UserInfo endpoint returned status %d: %v", resp.StatusCode, errorBody)
			return c.Status(resp.StatusCode).JSON(fiber.Map{
				"error":            "Error from userinfo endpoint",
				"status_code":      resp.StatusCode,
				"ms_error_details": errorBody,
			})
		}
		log.Printf("UserInfo endpoint returned status %d", resp.StatusCode)
		return c.Status(resp.StatusCode).JSON(fiber.Map{
			"error":       "Error from userinfo endpoint",
			"status_code": resp.StatusCode,
		})
	}

	var userInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("Error decoding UserInfo response: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not decode userinfo response",
		})
	}

	return c.JSON(userInfo)
}
