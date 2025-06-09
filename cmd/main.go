package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	applogger "github.com/SimpnicServerTeam/scs-aaa-server/internal/logger"
	ent_repo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/memory"
	redis_repo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/redis"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/router"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/server"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/service"
	"github.com/redis/go-redis/v9"
	zlog "github.com/rs/zerolog/log" // zerolog's global logger

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	applogger.Init(cfg.App.LogLevel, cfg.App.Env)
	redisClient := redis.NewClient(cfg.RedisSettings)
	entClient, err := ent.Open(cfg.Database.DatabaseDriver, cfg.Database.DSN)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed opening connection to database")
	}
	defer entClient.Close()
	// Run the auto migration tool.
	if err := entClient.Schema.Create(context.Background()); err != nil {
		zlog.Fatal().Err(err).Msg("Failed creating schema resources")
	}

	sessionRepo := redis_repo.NewRedisSessionRepository(redisClient)
	userRepo := ent_repo.NewEntUserRepository(entClient)
	verificationTokenRepo := redis_repo.NewRedisVerificationTokenRepository(redisClient)
	stateRepo := memory.NewMemoryStateRepository()

	tokenService := service.NewTokenService(cfg.App.JWTSecret)
	emailService := service.NewSMTPEmailService(&cfg.SMTP)
	sessionService := service.NewSessionService(sessionRepo, userRepo, tokenService)
	userService := service.NewUserService(userRepo)

	app := server.New(zlog.Logger)

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
		zlog.Info().Str("port", cfg.App.Port).Msg("Server starting")
		if err := app.Start(":" + cfg.App.Port); err != nil && err != http.ErrServerClosed {
			zlog.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	<-quit
	zlog.Info().Msg("Shutting down server...")

	if err := app.Shutdown(context.Background()); err != nil {
		zlog.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	zlog.Info().Msg("Server stopped gracefully.")

}
