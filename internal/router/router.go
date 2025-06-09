package router

import (
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/middleware"
	"github.com/labstack/echo/v4"
)

func SetupUserRoutes(e *echo.Echo, userHandler *handlers.UserHandler, cfg *config.Config) {
	sessionGroup := e.Group("/api/auth/sessions")

	sessionGroup.Use(middleware.JWTMiddleware(cfg.App.JWTSecret))
	sessionGroup.GET("/list", userHandler.GetUserSessions)
	sessionGroup.POST("/verify", userHandler.VerifyToken)
	sessionGroup.POST("/logout", userHandler.Logout)
	sessionGroup.POST("/logout-all", userHandler.LogoutAllSessions)

	userGroup := e.Group("/api/auth/users")

	userGroup.Use(middleware.JWTMiddleware(cfg.App.JWTSecret))
	userGroup.PUT("/", userHandler.UpdateUser)
	userGroup.DELETE("/", userHandler.DeleteUser)
}

func SetupSRPRoutes(e *echo.Echo, authHandler *handlers.SRPAuthHandler, cfg *config.Config) {
	api := e.Group("/api/auth/srp")

	api.POST("/sign-up/check", authHandler.CheckEmailExists)                          // Check if email is already in the DB, kinda unsafe for enumeration attacks, but whatever that's the flow
	api.POST("/sign-up", authHandler.Register)                                        // User registration
	api.POST("/sign-up/verification", authHandler.GenerateCodeAndSendActivationEmail) // Send activation email (if not activated)
	api.POST("/sign-up/activate", authHandler.ActivateAccount)                        // Activate the account
	api.POST("/login/email", authHandler.AuthStep1)                                   // SRP Step 1 (client sends email)
	api.POST("/login/proof", authHandler.AuthStep2)                                   // SRP Step 2 (client sends proof)

	api.POST("/password/reset", authHandler.InitiatePasswordReset)               // Send a reset email if the email is in the database
	api.POST("/password/reset/validate", authHandler.ValidatePasswordResetToken) // Validate if the reset token is valid
	api.POST("/password/reset/complete", authHandler.CompletePasswordReset)      // Used reset token and new salt and verifier to set a new password

	api.POST("/password/change/initiate", authHandler.InitiatePasswordChangeVerification, middleware.JWTMiddleware(cfg.App.JWTSecret)) // need to ask client to check step 2
	api.POST("/password/change/confirm", authHandler.ConfirmPasswordChange, middleware.JWTMiddleware(cfg.App.JWTSecret))               // need to do logout-all for the client
}

func SetupOAuthRoutes(e *echo.Echo, oauthHandler *handlers.OAuthHandler) {
	oauth := e.Group("/api/auth/oauth")
	ms := oauth.Group("/microsoft")
	ms.GET("/login", oauthHandler.Login)
	ms.GET("/callback", oauthHandler.Callback)
	ms.GET("/mobile", oauthHandler.MobileLogin)
}
