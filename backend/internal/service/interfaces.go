package service

import (
	"context"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
	"golang.org/x/oauth2"
)

// TokenService handles JWT generation
type TokenService struct {
	jwtSecret []byte
}

// SRPAuthService handles the core SRP logic
type SRPAuthService struct {
	userRepo  repository.UserRepository
	stateRepo repository.StateRepository
	tokenSvc  TokenGenerator
	srpGroup  string
	cfg       *config.Config
}

type TokenGenerator interface {
	GenerateToken(username string) (string, error)
}

type SRPAuthGenerator interface {
	// Register handles user registration
	Register(ctx context.Context, req models.SRPRegisterRequest) error
	// ComputeB handles SRP step 1 (Server -> Client: salt, B)
	ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error)
	// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
	VerifyClientProof(ctx context.Context, req models.AuthStep2Request) (*models.AuthStep3Response, error)
}

// OAuthService handles interactions with the OAuth2 provider
type OAuthService struct {
	Config      *config.Config
	OAuthConfig *oauth2.Config
	API         string
}

type OAuthProvider interface {
	GetAuthCodeURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*models.OAuthUser, error)
}
