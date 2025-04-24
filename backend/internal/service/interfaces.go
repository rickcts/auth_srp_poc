package service

import (
	"context"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
)

// TokenService handles JWT generation
type TokenService struct {
	jwtSecret []byte
}

// AuthService handles the core SRP logic
type AuthService struct {
	userRepo  repository.UserRepository
	stateRepo repository.StateRepository
	tokenSvc  TokenGenerator
	srpGroup  string
	cfg       *config.Config
}

type TokenGenerator interface {
	GenerateToken(username string) (string, error)
}

type AuthGenerator interface {
	// Register handles user registration
	Register(ctx context.Context, req models.RegisterRequest) error
	// ComputeB handles SRP step 1 (Server -> Client: salt, B)
	ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error)
	// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
	VerifyClientProof(ctx context.Context, req models.AuthStep2Request) (*models.AuthStep3Response, error)
}
