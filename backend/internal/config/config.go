package config

import (
	"crypto"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tadglines/go-pkgs/crypto/srp"
)

type Config struct {
	Port      string
	JWTSecret string
	// The set of supported groups are:
	// 		rfc5054.1024
	//		rfc5054.1536
	//		rfc5054.2048
	//		rfc5054.3072
	//		rfc5054.4096
	//		rfc5054.6144
	//		rfc5054.8192
	// 		stanford.1024
	//		stanford.1536
	//		stanford.2048
	//		stanford.3072
	//		stanford.4096
	//		stanford.6144
	//		stanford.8192
	// Default to rfc5054.4096
	SRPGroup         string
	AuthStateExpiry  time.Time
	HashingAlgorithm crypto.Hash
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
	var SRPGroupEnv string
	SRPGroupEnv = os.Getenv("SRP_GROUP_BITS")
	_, err := srp.GetGroup(SRPGroupEnv)
	if err != nil {
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
	hashingAlgorithmStr := os.Getenv("HASHING_ALGORITHM")

	var hashingAlgorithm crypto.Hash
	switch hashingAlgorithmStr {
	case "SHA1":
		hashingAlgorithm = crypto.SHA1
	case "SHA256":
		hashingAlgorithm = crypto.SHA256
	case "SHA512":
		hashingAlgorithm = crypto.SHA512
	default:
		hashingAlgorithm = crypto.SHA512
	}

	return &Config{
		Port:             port,
		JWTSecret:        jwtSecret,
		SRPGroup:         SRPGroupEnv,
		AuthStateExpiry:  authStateExpiry,
		HashingAlgorithm: hashingAlgorithm,
	}, nil
}
