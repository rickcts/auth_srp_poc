package router

import (
	"github.com/rickcts/srp/internal/handlers"

	"github.com/gofiber/fiber/v2"
)

func SetupJWTRoutes(app *fiber.App) {
	api := app.Group("/api/auth/jwt")
	api.Get("refresh") // Refresh access token
	api.Get("verify")  // Verify token
	api.Get("logout")  // Logout
}

func SetupSRPRoutes(app *fiber.App, authHandler *handlers.SRPAuthHandler) {
	api := app.Group("/api/auth/srp")

	api.Get("/sign-up/email")                       // Check if email is already in the DB, kinda unsafe but whatever that's the flow
	api.Post("/sign-up", authHandler.Register)      // User registration
	api.Post("/login/email", authHandler.AuthStep1) // SRP Step 1 (Client sends email)
	api.Post("/login/proof", authHandler.AuthStep2) // SRP Step 2 (Client sends proof)

}

func SetupOAuthRoutes(app *fiber.App, authHandler *handlers.OAuthHandler) {
	oauth := app.Group("/api/auth/oauth")

	ms := oauth.Group("/microsoft")
	ms.Get("/login", authHandler.Login)
	ms.Get("/callback", authHandler.Callback)
}
