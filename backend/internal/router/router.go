package router

import (
	"github.com/rickcts/srp/internal/handler"

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes defines authentication routes
func SetupRoutes(app *fiber.App, authHandler *handler.AuthHandler) {
	api := app.Group("/api/auth/srp")

	api.Post("/register", authHandler.Register)     // User registration
	api.Post("/login/step1", authHandler.AuthStep1) // SRP Step 1 (Client sends )
	api.Post("/login/step2", authHandler.AuthStep2) // SRP Step 2 (Client sends M1)
}
