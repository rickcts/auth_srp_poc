package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/handler"
	"github.com/rickcts/srp/internal/repository/memory"
	"github.com/rickcts/srp/internal/router"
	"github.com/rickcts/srp/internal/server"
	"github.com/rickcts/srp/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	userRepo := memory.NewMemoryUserRepository()
	stateRepo := memory.NewMemoryStateRepository()

	tokenService := service.NewTokenService(cfg.JWTSecret)
	authService := service.NewAuthService(userRepo, stateRepo, tokenService, cfg)

	authHandler := handler.NewAuthHandler(authService)

	app := server.New()

	router.SetupRoutes(app, authHandler)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Server starting on port %s...", cfg.Port)
		if err := app.Listen(":" + cfg.Port); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	<-quit
	log.Println("Shutting down server...")

	if err := app.Shutdown(); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped gracefully.")
}
