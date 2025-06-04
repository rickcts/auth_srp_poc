package mocks

import (
	"crypto"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
)

func CreateTestConfigForSessionTests() *config.Config {
	return &config.Config{
		JWTSecret: "test-jwt-secret-for-session-tests",
		SRP: config.SRPConfig{
			Group:            "rfc5054.4096", // Example value
			AuthStateExpiry:  time.Now().Add(5 * time.Minute),
			HashingAlgorithm: crypto.SHA256, // Example value
		},
		Security: config.SecurityConfig{
			PasswordResetTokenExpiry: 15 * time.Minute,
		},
	}
}
