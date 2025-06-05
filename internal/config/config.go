package config

import (
	"crypto"
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"
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

type SessionConfig struct {
	AccessTokenDuration  time.Duration `mapstructure:"accessTokenDuration"`
	RefreshTokenDuration time.Duration `mapstructure:"refreshTokenDuration"`
}

type RedisSettings struct {
	Address  string
	Password string
	DB       int
}

type SecurityConfig struct {
	PasswordResetTokenExpiry time.Duration `mapstructure:"PASSWORD_RESET_TOKEN_EXPIRY"` // e.g., "15m"
}

type SmtpConfig struct {
	Host     string `mapstructure:"SMTP_HOST"`
	Port     string `mapstructure:"SMTP_PORT"`
	User     string `mapstructure:"SMTP_USER"`
	Password string `mapstructure:"SMTP_PASSWORD"`
	NOTLS    bool   `mapstructure:"SMTP_NOTLS"`
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
	RedisSettings    RedisSettings
	SessionConfig    SessionConfig
	SMTP             SmtpConfig     `mapstructure:",squash"`
	Security         SecurityConfig `mapstructure:",squash"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()

	// Load configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("Config file not found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	// JWT Secret
	jwtSecret := viper.GetString("JWT_SECRET")
	if jwtSecret == "a_very_secret_key_change_me" {
		fmt.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable or in config file.")
	}

	// SRP Configuration
	srpGroup := viper.GetString("SRP_GROUP_BITS")
	if _, err := srp.GetGroup(srpGroup); err != nil {
		srpGroup = "rfc5054.4096"
		log.Printf("Invalid SRP group '%s', defaulting to '%s'", viper.GetString("SRP_GROUP_BITS"), srpGroup)
	}

	expirySeconds := viper.GetInt("SRP_AUTH_STATE_EXPIRY_SECONDS")
	if expirySeconds <= 0 {
		expirySeconds = 300
	}
	srpAuthStateExpiry := time.Now().Add(time.Duration(expirySeconds) * time.Second)

	hashingAlgorithmStr := viper.GetString("HASHING_ALGORITHM")
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
		log.Printf("Invalid hashing algorithm '%s', defaulting to SHA512", hashingAlgorithmStr)
	}

	// Database Configuration
	databaseDriver := viper.GetString("DATABASE_DRIVER")
	var databaseSettings string
	if databaseDriver == "sqlite3" {
		databaseSettings = "file:ent?mode=memory&cache=shared&_fk=1"
	} else {
		databaseSettings = fmt.Sprintf(
			"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
			viper.GetString("DB_HOST"),
			viper.GetInt("DB_PORT"),
			viper.GetString("DB_USER"),
			viper.GetString("DB_NAME"),
			viper.GetString("DB_PASS"),
			viper.GetString("DB_SSL_MODE"),
		)
	}

	// OAuth Configuration
	oauthProviders := make(map[string]*oauth2.Config)
	oauthProviders["MICROSOFT"] = &oauth2.Config{
		ClientID:     viper.GetString("MICROSOFT_CLIENT_ID"),
		ClientSecret: viper.GetString("MICROSOFT_CLIENT_SECRET"),
		RedirectURL:  viper.GetString("MICROSOFT_REDIRECT_URL"),
		Scopes:       []string{"openid", "profile", "email", "offline_access", "User.Read"},
		Endpoint:     microsoft.AzureADEndpoint("consumers"),
	}

	return &Config{
		Port:      viper.GetString("APP_PORT"),
		JWTSecret: jwtSecret,
		SRP: SRPConfig{
			Group:            srpGroup,
			AuthStateExpiry:  srpAuthStateExpiry,
			HashingAlgorithm: hashingAlgorithm,
		},
		OAuthProviders:   oauthProviders,
		DatabaseSettings: databaseSettings,
		DatabaseDriver:   databaseDriver,
		StateCookieName:  viper.GetString("STATE_COOKIE_NAME"),
		RedisSettings: RedisSettings{
			Address:  viper.GetString("REDIS_ADDRESS"),
			Password: viper.GetString("REDIS_PASSWORD"),
			DB:       viper.GetInt("REDIS_DB"),
		},
		SMTP: SmtpConfig{
			Host:     viper.GetString("SMTP_HOST"),
			Port:     viper.GetString("SMTP_PORT"),
			User:     viper.GetString("SMTP_USER"),
			Password: viper.GetString("SMTP_PASSWORD"),
			NOTLS:    viper.GetBool("SMTP_NOTLS"),
		},
	}, nil
}
