package main

import (
	"context"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/logger"
	entrepo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/memory"
	redisrepo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/redis"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/router"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/server"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		stdlog.Fatalf("Failed to load configuration: %v", err)
	}

	logger.Init(cfg.App.LogLevel, cfg.App.Env)
	redisClient := redis.NewClient(cfg.RedisSettings)
	// Test Redis connection
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	} else {
		log.Info().Msg("Successfully connected to Redis")
	}

	entClient, err := ent.Open(cfg.Database.DatabaseDriver, cfg.Database.DSN)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed opening connection to database")
	}
	defer entClient.Close()
	// Run the auto migration tool.
	if err := entClient.Schema.Create(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed creating schema resources")
	}

	sessionRepo := redisrepo.NewRedisSessionRepository(redisClient)
	userRepo := entrepo.NewEntUserRepository(entClient)
	verificationTokenRepo := redisrepo.NewRedisVerificationTokenRepository(redisClient)
	stateRepo := memory.NewMemoryStateRepository()

	tokenService := service.NewTokenService(cfg.App.JWTSecret)
	emailService := service.NewSMTPEmailService(&cfg.SMTP)
	sessionService := service.NewSessionService(sessionRepo, userRepo, tokenService)
	userService := service.NewUserService(userRepo)

	app := server.New(log.Logger)

	router.SetupUserRoutes(app, handlers.NewUserHandler(tokenService, sessionService, userService), cfg)
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
		if err := app.Start(":" + cfg.App.Port); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	<-quit
	log.Info().Msg("Shutting down server...")

	if err := app.Shutdown(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server stopped gracefully.")

}
