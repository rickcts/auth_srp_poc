package config

import (
	"crypto"
	"fmt"

	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/tadglines/go-pkgs/crypto/srp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type APPConfig struct {
	Name            string
	Port            string
	JWTSecret       string
	StateCookieName string
	LogLevel        string
	Env             string // e.g., "development", "production"
}

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
	// Default to rfc5054.4096.
	Group string
	// AuthStateExpiry sets the expiry time for the SRP authentication state (e.g., "5m", "300s").
	// This is the duration for which the server keeps temporary state during the SRP handshake.
	AuthStateExpiry  time.Duration
	HashingAlgorithm crypto.Hash
}

type SessionConfig struct {
	AccessTokenDuration time.Duration
	ValidationDuration  time.Duration
}

type RedisSettings struct {
	Address  string
	Password string
	DB       int
}

type DatabaseSettings struct {
	DatabaseDriver string
	// host=<host> port=<port> user=<user> dbname=<database> password=<pass> sslmode=<enable/disable>
	DSN string
}

type SmtpConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	NOTLS    bool
}

type Config struct {
	// Server port
	App           APPConfig
	SRP           SRPConfig
	OAuth         map[string]*oauth2.Config
	Database      DatabaseSettings
	RedisSettings *redis.Options
	SessionConfig SessionConfig
	SMTP          SmtpConfig
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	viper.SetDefault("app.port", "8080")
	viper.SetDefault("app.jwtSecret", "a_very_secret_key_change_me_in_config_yaml")
	viper.SetDefault("app.stateCookieName", "my_oauth_state_cookie")
	viper.SetDefault("app.logLevel", "info")
	viper.SetDefault("app.env", "development")

	viper.SetDefault("srp.group", "rfc5054.4096")
	viper.SetDefault("srp.authStateExpiry", "5m")
	viper.SetDefault("srp.hashingAlgorithm", "SHA512")

	viper.SetDefault("database.driver", "sqlite3")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.name", "app_db")
	viper.SetDefault("database.pass", "password")
	viper.SetDefault("database.sslMode", "disable")

	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	viper.SetDefault("sessionConfig.accessTokenDuration", "1h")
	viper.SetDefault("sessionConfig.refreshTokenDuration", "168h") // 7 days

	viper.SetDefault("smtp.host", "")
	viper.SetDefault("smtp.port", "587")
	viper.SetDefault("smtp.user", "")
	viper.SetDefault("smtp.password", "")
	viper.SetDefault("smtp.noTls", false)

	viper.SetDefault("security.passwordResetTokenExpiry", "15m")

	viper.SetDefault("oauthProviders.microsoft.clientID", "")
	viper.SetDefault("oauthProviders.microsoft.clientSecret", "")
	viper.SetDefault("oauthProviders.microsoft.redirectURL", "http://localhost:8080/api/auth/oauth/microsoft/callback")
	viper.SetDefault("oauthProviders.microsoft.scopes", []string{"openid", "profile", "email"})
	viper.SetDefault("oauthProviders.microsoft.tenant", "common")

	// Load configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("Config file (config.yaml) not found, using defaults and environment variables.")

		} else {
			return nil, err // Return the original error
		}
	}

	// JWT Secret
	jwtSecret := viper.GetString("app.jwtSecret")
	if jwtSecret == "a_very_secret_key_change_me_in_config_yaml" || jwtSecret == "a_very_secret_key_change_me" {
		log.Println("Using default JWT secret. Set app.jwtSecret in your config.yaml or the JWT_SECRET environment variable.")
	}

	// SRP Configuration
	srpGroup := viper.GetString("srp.group")
	if _, err := srp.GetGroup(srpGroup); err != nil {
		srpGroup = "rfc5054.4096"
		log.Println("Invalid SRP group in srp.group, defaulting to rfc5054.4096")
	}

	srpAuthStateExpiryDuration := viper.GetDuration("srp.authStateExpiry")
	if srpAuthStateExpiryDuration <= 0 {
		log.Println("Invalid or missing srp.authStateExpiry, defaulting to 5m.")
		srpAuthStateExpiryDuration = 5 * time.Minute
	}

	hashingAlgorithmStr := viper.GetString("srp.hashingAlgorithm")
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
		log.Println("Invalid hashing algorithm in srp.hashingAlgorithm, defaulting to SHA512")
	}

	// Token Configuration
	accessTokenDuration := viper.GetDuration("sessionConfig.accessTokenDuration")
	if accessTokenDuration <= 0 {
		log.Println("Invalid or missing sessionConfig.accessTokenDuration, defaulting to 1h")
		accessTokenDuration = 1 * time.Hour
	}

	validationTokenDuration := viper.GetDuration("security.validationTokenDuration")
	if validationTokenDuration <= 0 {
		log.Println("Invalid or missing security.validationTokenDuration, defaulting to 5m")
		validationTokenDuration = 5 * time.Minute
	}

	// Database Configuration
	databaseDriver := viper.GetString("database.driver")
	var DSN string
	if databaseDriver == "sqlite3" {
		DSN = "file:ent?mode=memory&cache=shared&_fk=1"
	} else {
		DSN = fmt.Sprintf(
			"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
			viper.GetString("database.host"),
			viper.GetInt("database.port"),
			viper.GetString("database.user"),
			viper.GetString("database.name"),
			viper.GetString("database.pass"),
			viper.GetString("database.sslMode"),
		)
	}

	// OAuth Configuration
	oauthProviders := make(map[string]*oauth2.Config)
	oauthProviders["MICROSOFT"] = &oauth2.Config{
		ClientID:     viper.GetString("oauthProviders.microsoft.clientID"),
		ClientSecret: viper.GetString("oauthProviders.microsoft.clientSecret"),
		RedirectURL:  viper.GetString("oauthProviders.microsoft.redirectURL"),
		Scopes:       viper.GetStringSlice("oauthProviders.microsoft.scopes"),
		Endpoint:     microsoft.AzureADEndpoint(viper.GetString("oauthProviders.microsoft.tenant")),
	}

	return &Config{
		App: APPConfig{
			Name:            viper.GetString("app.name"),
			Port:            viper.GetString("app.port"),
			JWTSecret:       jwtSecret,
			LogLevel:        viper.GetString("app.logLevel"),
			Env:             viper.GetString("app.env"),
			StateCookieName: viper.GetString("app.stateCookieName"),
		},
		SRP: SRPConfig{
			Group:            srpGroup,
			AuthStateExpiry:  srpAuthStateExpiryDuration,
			HashingAlgorithm: hashingAlgorithm,
		},
		OAuth: oauthProviders,
		Database: DatabaseSettings{
			DatabaseDriver: databaseDriver,
			DSN:            DSN,
		},
		RedisSettings: &redis.Options{
			Addr:     viper.GetString("redis.address"),
			Password: viper.GetString("redis.password"),
			DB:       viper.GetInt("redis.db"),
		},
		SessionConfig: SessionConfig{
			AccessTokenDuration: accessTokenDuration,
			ValidationDuration:  validationTokenDuration,
		},
		SMTP: SmtpConfig{
			Host:     viper.GetString("smtp.host"),
			Port:     viper.GetString("smtp.port"),
			User:     viper.GetString("smtp.user"),
			Password: viper.GetString("smtp.password"),
			NOTLS:    viper.GetBool("smtp.noTls"),
		},
	}, nil
}
