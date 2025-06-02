package router

import (
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/gofiber/fiber/v2"
)

func SetupJWTRoutes(app *fiber.App, authHandler *handlers.JWTAuthHandler) {
	// api := app.Group("/api/auth/jwt")
	// // api.Get("/refresh", authHandler.RefreshToken) // This route is removed
	// api.Post("/verify", authHandler.VerifyToken)          // Verify current session token (expects token in Auth header)
	// api.Get("/logout", authHandler.Logout)                // Logout current session (expects token in Auth header)
	// api.Post("/logout-all", authHandler.LogoutAllDevices) // Logout all other sessions for the authenticated user
}

func SetupSRPRoutes(app *fiber.App, authHandler *handlers.SRPAuthHandler) {
	api := app.Group("/api/auth/srp")

	// api.Get("/sign-up/email")                       // Check if email is already in the DB, kinda unsafe but whatever that's the flow
	api.Post("/sign-up", authHandler.Register)      // User registration
	api.Post("/login/email", authHandler.AuthStep1) // SRP Step 1 (Client sends email)
	api.Post("/login/proof", authHandler.AuthStep2) // SRP Step 2 (Client sends proof)
	api.Put("/password", authHandler.ChangePassword)
}

func SetupOAuthRoutes(app *fiber.App, oauthHandler *handlers.OAuthHandler) {
	oauth := app.Group("/api/auth/oauth")
	protectedAPI := app.Group("/api") // Apply AuthMiddleware here

	protectedAPI.Get("/protected", func(c *fiber.Ctx) error {
		// Access claims stored in c.Locals by the middleware
		userID, ok := c.Locals("userID").(string) // Changed from "userClaims" to "userID"
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to retrieve user claims",
			})
		}
		return c.JSON(fiber.Map{
			"message": "You have accessed a protected route!",
			"userID":  userID,
		})
	})
	ms := oauth.Group("/microsoft")
	ms.Get("/login", oauthHandler.Login)
	ms.Get("/callback", oauthHandler.Callback)
	ms.Get("/mobile", oauthHandler.MobileLogin)
}
