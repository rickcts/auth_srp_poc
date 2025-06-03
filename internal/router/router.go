package router

import (
	"net/http"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/labstack/echo/v4"
)

func SetupJWTRoutes(e *echo.Echo, authHandler *handlers.JWTAuthHandler) {
	// api := e.Group("/api/auth/jwt")
	// // api.Get("/refresh", authHandler.RefreshToken) // This route is removed
	// api.POST("/verify", authHandler.VerifyToken)          // Verify current session token (expects token in Auth header)
	// api.GET("/logout", authHandler.Logout)                // Logout current session (expects token in Auth header)
	// api.POST("/logout-all", authHandler.LogoutAllDevices) // Logout all other sessions for the authenticated user
}

func SetupSRPRoutes(e *echo.Echo, authHandler *handlers.SRPAuthHandler) {
	api := e.Group("/api/auth/srp")

	// api.Get("/sign-up/email")                       // Check if email is already in the DB, kinda unsafe but whatever that's the flow
	api.POST("/sign-up", authHandler.Register)      // User registration
	api.POST("/login/email", authHandler.AuthStep1) // SRP Step 1 (Client sends email)
	api.POST("/login/proof", authHandler.AuthStep2) // SRP Step 2 (Client sends proof)
	api.PUT("/password", authHandler.ChangePassword)
}

func SetupOAuthRoutes(e *echo.Echo, oauthHandler *handlers.OAuthHandler) {
	oauth := e.Group("/api/auth/oauth")
	protectedAPI := e.Group("/api") // Apply AuthMiddleware here (ensure middleware is Echo compatible)

	protectedAPI.GET("/protected", func(c echo.Context) error {
		// Access claims stored in c.Locals by the middleware
		userID, ok := c.Get("userID").(string) // Use c.Get for Echo context values
		if !ok {
			return c.JSON(http.StatusInternalServerError, echo.Map{
				"error": "Failed to retrieve user claims",
			})
		}
		return c.JSON(http.StatusOK, echo.Map{
			"message": "You have accessed a protected route!",
			"userID":  userID,
		})
	})
	ms := oauth.Group("/microsoft")
	ms.GET("/login", oauthHandler.Login)
	ms.GET("/callback", oauthHandler.Callback)
	ms.GET("/mobile", oauthHandler.MobileLogin)
}
