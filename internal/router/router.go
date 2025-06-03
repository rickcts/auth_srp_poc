package router

import (
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/middleware"
	"github.com/labstack/echo/v4"
)

func SetupUserRoutes(e *echo.Echo, authHandler *handlers.JWTAuthHandler, cfg *config.Config) {
	api := e.Group("/api/auth/user")
	api.Use(middleware.JWTMiddleware(cfg.JWTSecret))
	api.POST("/verify", authHandler.VerifyToken)          // Verify current session token
	api.GET("/logout", authHandler.Logout)                // Logout current session
	api.POST("/logout-all", authHandler.LogoutAllDevices) // Logout all other sessions for the authenticated user
}

func SetupSRPRoutes(e *echo.Echo, authHandler *handlers.SRPAuthHandler) {
	api := e.Group("/api/auth/srp")

	api.GET("/sign-up/email", authHandler.CheckEmailExists) // Check if email is already in the DB, kinda unsafe but whatever that's the flow
	api.POST("/sign-up", authHandler.Register)              // User registration
	api.POST("/login/email", authHandler.AuthStep1)         // SRP Step 1 (Client sends email)
	api.POST("/login/proof", authHandler.AuthStep2)         // SRP Step 2 (Client sends proof)
	api.PUT("/password", authHandler.ChangePassword)
}

func SetupOAuthRoutes(e *echo.Echo, oauthHandler *handlers.OAuthHandler) {
	oauth := e.Group("/api/auth/oauth")
	ms := oauth.Group("/microsoft")
	ms.GET("/login", oauthHandler.Login)
	ms.GET("/callback", oauthHandler.Callback)
	ms.GET("/mobile", oauthHandler.MobileLogin)
}
