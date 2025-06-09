package mocks

import (
	"crypto"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
)

func CreateTestConfigForSessionTests() *config.Config {
	return &config.Config{
		App: config.APPConfig{
			Name:      "test-app",
			Port:      "8080",
			JWTSecret: "test-jwt-secret-for-session-tests",
		},
		SRP: config.SRPConfig{
			Group:            "rfc5054.4096", // Example value
			AuthStateExpiry:  5 * time.Minute,
			HashingAlgorithm: crypto.SHA256, // Example value
		},
		SessionConfig: config.SessionConfig{
			AccessTokenDuration: 1 * time.Hour,
			ValidationDuration:  15 * time.Minute,
		},
	}
}
