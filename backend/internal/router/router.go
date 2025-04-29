package router

import (
	"github.com/rickcts/srp/internal/handler"

	"github.com/gofiber/fiber/v2"
)

// SetupSRPRoutes defines authentication routes
func SetupSRPRoutes(app *fiber.App, authHandler *handler.SRPAuthHandler) {
	api := app.Group("/api/auth/srp")

	api.Post("/register", authHandler.Register)     // User registration
	api.Post("/login/step1", authHandler.AuthStep1) // SRP Step 1 (Client sends )
	api.Post("/login/step2", authHandler.AuthStep2) // SRP Step 2 (Client sends M1)

}

func SetupOAuthRoutes(app *fiber.App, authHandler *handler.OAuthHandler) {
	oauth := app.Group("/api/auth/oauth")

	ms := oauth.Group("/microsoft")
	ms.Get("/login", authHandler.Login)
	// IMPORTANT: The path here MUST match the Redirect URI configured in Azure AD
	ms.Get("/callback", authHandler.Callback)
}
