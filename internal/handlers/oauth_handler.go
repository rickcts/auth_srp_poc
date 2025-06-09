package handlers

import (
	"net/http"
	"time"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
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
func (h *OAuthHandler) Login(c echo.Context) error {
	state := uuid.NewString()

	cookie := new(http.Cookie)
	cookie.Name = h.Config.App.StateCookieName
	cookie.Value = state
	cookie.Expires = time.Now().UTC().Add(10 * time.Minute) // Short expiry
	cookie.HttpOnly = true                                  // Prevent client-side script access
	cookie.Secure = c.Scheme() == "https"                   // Set Secure flag if using HTTPS
	cookie.SameSite = http.SameSiteLaxMode                  // Lax is usually sufficient for OAuth redirects
	c.SetCookie(cookie)

	authURL := h.OAuthService.GetAuthCodeURL(state)
	log.Info().Str("url", authURL).Msg("Redirecting user for OAuth login")

	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles the web redirect back from Microsoft after authentication
func (h *OAuthHandler) Callback(c echo.Context) error {
	// --- State Verification (CSRF Protection) ---
	queryState := c.QueryParam("state")
	cookieStateCookie, err := c.Cookie(h.Config.App.StateCookieName)
	var cookieStateValue string
	if err == nil && cookieStateCookie != nil {
		cookieStateValue = cookieStateCookie.Value
	}

	// Clear the state cookie immediately after reading
	clearCookie := new(http.Cookie)
	clearCookie.Name = h.Config.App.StateCookieName
	clearCookie.Value = ""
	clearCookie.Expires = time.Now().UTC().Add(-1 * time.Hour) // Expire immediately
	clearCookie.HttpOnly = true
	clearCookie.Secure = c.Scheme() == "https"
	clearCookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(clearCookie)

	if queryState == "" {
		log.Warn().Msg("Callback error: state parameter missing in callback URL")
		return echo.NewHTTPError(http.StatusBadRequest, "State parameter missing")
	}
	if cookieStateValue == "" { // Check if cookie was missing or value was empty
		log.Warn().Msg("Callback error: state cookie missing or empty")
		return echo.NewHTTPError(http.StatusBadRequest, "State cookie missing or expired")
	}
	if queryState != cookieStateValue {
		log.Warn().Str("queryState", queryState).Str("cookieState", cookieStateValue).Msg("Callback error: state mismatch")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid state parameter")
	}
	log.Info().Msg("State verification successful")

	code := c.QueryParam("code")
	if code == "" {
		errorDesc := c.QueryParam("error_description")
		log.Warn().Str("oauthError", c.QueryParam("error")).Str("errorDescription", errorDesc).Msg("Callback error: authorization code missing")
		// Return a generic message to the client, but log the specific OAuth error
		return echo.NewHTTPError(http.StatusBadRequest, "Authorization code missing or error occurred during login.")
	}
	log.Info().Msg("Authorization code received")

	token, err := h.OAuthService.ExchangeCode(c.Request().Context(), code) // Use request context
	if err != nil {
		log.Error().Err(err).Msg("Error exchanging code in callback")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to exchange authorization code for token")
	}
	log.Info().Msg("Token exchange successful")

	// --- Fetch User Info ---
	user, err := h.OAuthService.ProcessUserInfo(c.Request().Context(), token, "MICROSOFT") // Use request context
	if err != nil {
		log.Error().Err(err).Msg("Error fetching user info in callback")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user information")
	}
	log.Info().Str("displayName", user.DisplayName).Str("email", user.Email).Msg("Successfully logged in user via OAuth callback")

	// For this example, just return the user info as JSON
	return c.JSON(http.StatusOK, echo.Map{
		"message": "Login successful!",
		"user":    user,
		// "access_token": token.AccessToken,
	})
}

// MobileLogin handles the token exchange initiated by a mobile application.
func (h *OAuthHandler) MobileLogin(c echo.Context) error {
	var req models.MobileLoginRequest
	if err := c.Bind(&req); err != nil {
		log.Warn().Err(err).Msg("MobileLogin error: Failed to parse request body")
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	if req.Code == "" || req.CodeVerifier == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing code or code_verifier")
	}
	log.Info().Str("authProvider", req.AuthProvider).Msg("MobileLogin: Received code and verifier.")

	oauth2token, err := h.OAuthService.ExchangeCodeMobile(c.Request().Context(), req.Code, req.CodeVerifier, req.AuthProvider)
	if err != nil {
		log.Error().Err(err).Str("authProvider", req.AuthProvider).Msg("MobileLogin error: Failed to exchange code")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to authenticate with provider")
	}
	log.Info().Str("authProvider", req.AuthProvider).Msg("MobileLogin: Token exchange successful.")

	user, err := h.OAuthService.ProcessUserInfo(c.Request().Context(), oauth2token, req.AuthProvider)
	if err != nil {
		log.Error().Err(err).Str("authProvider", req.AuthProvider).Msg("MobileLogin error: Failed to fetch user info")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user information")
	}
	log.Info().Str("displayName", user.DisplayName).Str("email", user.Email).Str("authProvider", req.AuthProvider).Msg("MobileLogin: Successfully logged in user")

	return c.JSON(http.StatusCreated, echo.Map{
		"message": "Login successful!",
		"user":    user,
	})
}

func (h *OAuthHandler) GetUserInfoHandler(c echo.Context) error {
	accessToken, ok := c.Get("accessToken").(string) // c.Get for context values
	if !ok || accessToken == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Access token not found in context")
	}

	req, err := http.NewRequest("GET", "https://graph.microsoft.com/oidc/userinfo", nil)
	if err != nil {
		log.Error().Err(err).Msg("Error creating UserInfo request")
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not create request to userinfo endpoint")
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Error calling UserInfo endpoint")
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Failed to call userinfo endpoint")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorBody map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&errorBody); err == nil {
			log.Warn().Int("statusCode", resp.StatusCode).Interface("errorBody", errorBody).Msg("UserInfo endpoint returned non-OK status with body")
			return echo.NewHTTPError(resp.StatusCode, echo.Map{
				"error":            "Error from userinfo endpoint",
				"status_code":      resp.StatusCode,
				"ms_error_details": errorBody,
			})
		}
		log.Warn().Int("statusCode", resp.StatusCode).Msg("UserInfo endpoint returned non-OK status")
		return echo.NewHTTPError(resp.StatusCode, echo.Map{
			"error":       "Error from userinfo endpoint",
			"status_code": resp.StatusCode,
		})
	}
	var userInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Error().Err(err).Msg("Error decoding UserInfo response")
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not decode userinfo response")
	}

	return c.JSON(http.StatusOK, userInfo)
}
