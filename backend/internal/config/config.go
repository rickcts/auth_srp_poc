package config

import (
	"crypto"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tadglines/go-pkgs/crypto/srp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type SRPConfig struct {
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
	// Default to rfc5054.4096
	Group string
	// Set the expiry time between srp exchange
	AuthStateExpiry  time.Time
	HashingAlgorithm crypto.Hash
}
type Config struct {
	// Server port
	Port           string
	JWTSecret      string
	SRP            SRPConfig
	OAuthProviders map[string]*oauth2.Config
	DatabaseDriver string
	// host=<host> port=<port> user=<user> dbname=<database> password=<pass> sslmode=<enable/disable>
	DatabaseSettings string
	StateCookieName  string
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
	var srpGroupEnv string
	srpGroupEnv = os.Getenv("SRP_GROUP_BITS")
	_, err := srp.GetGroup(srpGroupEnv)
	if err != nil {
		srpGroupEnv = "rfc5054.4096"
	}

	authStateExpiryStr := os.Getenv("SRP_AUTH_STATE_EXPIRY_SECONDS")
	if authStateExpiryStr == "" {
		authStateExpiryStr = "120" // Default: 2 minutes
	}
	expirySeconds, err := strconv.Atoi(authStateExpiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_STATE_EXPIRY_SECONDS: %w", err)
	}
	srpAuthStateExpiry := time.Now().Add(time.Duration(expirySeconds) * time.Second)

	if srpAuthStateExpiry.IsZero() {
		return nil, fmt.Errorf("SRP_AUTH_STATE_EXPIRY_SECONDS cannot be zero")
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

	var databaseDriver string
	var databaseSettings string
	databaseDriver = os.Getenv("DATABASE_DRIVER")
	if databaseDriver == "" {
		databaseDriver = "sqlite3"
		databaseSettings = "file:ent?mode=memory&cache=shared&_fk=1"
	} else {
		databaseSettings = fmt.Sprintf(
			"host=%s port=%s user=%s dbname=%s password=%s sslmode=%s",
			getEnvOrDefault("DB_HOST", "localhost"),
			getEnvOrDefault("DB_PORT", "5432"),
			getEnvOrDefault("DB_USER", "postgres"),
			getEnvOrDefault("DB_NAME", "postgres"),
			getEnvOrDefault("DB_PASS", "postgres"),
			getEnvOrDefault("DB_SSL_MODE", "disable"),
		)
	}

	return &Config{
		Port:      port,
		JWTSecret: jwtSecret,
		SRP: SRPConfig{
			Group:            srpGroupEnv,
			AuthStateExpiry:  srpAuthStateExpiry,
			HashingAlgorithm: hashingAlgorithm,
		},
		OAuthProviders: map[string]*oauth2.Config{
			"microsoft": {
				ClientID:     getEnvOrDefault("MICROSOFT_CLIENT_ID", ""),
				ClientSecret: getEnvOrDefault("MICROSOFT_CLIENT_SECRET", ""),
				RedirectURL:  getEnvOrDefault("MICROSOFT_REDIRECT_URL", ""),
				Scopes:       []string{"openid", "profile", "email", "offline_access", "User.Read"},
				Endpoint:     microsoft.AzureADEndpoint("consumers"),
			},
		},
		DatabaseSettings: databaseSettings,
		DatabaseDriver:   "sqlite3",
		StateCookieName:  "oauth_state",
	}, nil

}

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
