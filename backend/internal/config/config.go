package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port            string
	JWTSecret       string
	SRPGroup        string
	AuthStateExpiry time.Time
}

func Load() (*Config, error) {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "3000"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "a_very_secret_key_change_me"
		fmt.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable.")
	}
	SRPGroupEnv := os.Getenv("SRP_GROUP_BITS")
	if SRPGroupEnv == "" {
		SRPGroupEnv = "rfc5054.4096"
	}

	authStateExpiryStr := os.Getenv("AUTH_STATE_EXPIRY_SECONDS")
	if authStateExpiryStr == "" {
		authStateExpiryStr = "120" // Default: 2 minutes
	}
	expirySeconds, err := strconv.Atoi(authStateExpiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_STATE_EXPIRY_SECONDS: %w", err)
	}
	authStateExpiry := time.Now().Add(time.Duration(expirySeconds) * time.Second)
	if authStateExpiry.IsZero() {
		return nil, fmt.Errorf("AUTH_STATE_EXPIRY_SECONDS cannot be zero")
	}

	return &Config{
		Port:            port,
		JWTSecret:       jwtSecret,
		SRPGroup:        SRPGroupEnv,
		AuthStateExpiry: authStateExpiry,
	}, nil
}
