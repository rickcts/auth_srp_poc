package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	ent_repo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/memory"
	redis_repo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/redis"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/router"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/server"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/redis/go-redis/v9"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: cfg.RedisSettings.Address,
	})

	entClient, err := ent.Open(cfg.DatabaseDriver, cfg.DatabaseSettings)
	if err != nil {
		log.Fatalf("failed opening connection to postgres: %v", err)
	}
	defer entClient.Close()
	// Run the auto migration tool.
	if err := entClient.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	sessionRepo := redis_repo.NewRedisSessionRepository(redisClient)
	userRepo := ent_repo.NewEntUserRepository(entClient)
	verificationTokenRepo := redis_repo.NewRedisVerificationTokenRepository(redisClient)
	stateRepo := memory.NewMemoryStateRepository()

	tokenService := service.NewTokenService(cfg.JWTSecret)
	emailService := service.NewSMTPEmailService(&cfg.SMTP)

	app := server.New()

	router.SetupSRPRoutes(app, handlers.NewSRPAuthHandler(
		service.NewSRPAuthService(
			userRepo,
			stateRepo,
			sessionRepo,
			tokenService,
			verificationTokenRepo,
			emailService,
			cfg,
		),
	), cfg)
	router.SetupOAuthRoutes(app, handlers.NewOAuthHandler(
		service.NewMSOAuthService(cfg, userRepo),
		cfg,
	))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("Server starting on port %s...", cfg.Port)
		if err := app.Start(":" + cfg.Port); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	<-quit
	log.Println("Shutting down server...")

	if err := app.Shutdown(context.Background()); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped gracefully.")

}
