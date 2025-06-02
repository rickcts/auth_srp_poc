package service

import (
	"context"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// JWTService handles JWT generation
type JWTService struct {
	jwtSecret []byte
}

// SRPAuthService handles the core SRP logic
type SRPAuthService struct {
	userRepo               repository.UserRepository
	stateRepo              repository.StateRepository
	tokenSvc               JWTGenerator
	srpGroup               string
	sessionRepo            repository.SessionRepository
	cfg                    *config.Config
	passwordResetTokenRepo repository.PasswordResetTokenRepository
	emailSvc               EmailService
}

type JWTGenerator interface {
	GenerateToken(userId int64) (token string, expiry time.Time, err error)
	ValidateToken(tokenString string) (userId int64, claims map[string]interface{}, err error)
}

type SessionGenerator interface {
	VerifySessionToken(ctx context.Context, sessionTokenID string) (*models.VerifyTokenResponse, error)
	ExtendUserSession(ctx context.Context, currentSessionToken string) (*models.ExtendedSessionResponse, error)
	SignOut(ctx context.Context, sessionToken string) error
	SignOutUserSessions(ctx context.Context, userId int64, currentSessionTokenToExclude ...string) (int64, error)
}

type SRPAuthGenerator interface {
	// Register handles user registration
	Register(ctx context.Context, req models.SRPRegisterRequest) error
	// ComputeB handles SRP step 1 (Server -> Client: salt, B)
	ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error)
	// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
	VerifyClientProof(ctx context.Context, req models.AuthStep2Request) (*models.AuthStep3Response, error)
	// ChangePassword handles changing the password for an authenticated user. AuthID is typically derived from the session.
	ChangePassword(ctx context.Context, authID string, req models.ChangePasswordRequest) error
	// InitiatePasswordReset starts the password reset flow for a user.
	InitiatePasswordReset(ctx context.Context, req models.InitiatePasswordResetRequest) error
	// CompletePasswordReset completes the password reset flow using a token and new credentials.
	CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error
}

// EmailService defines an interface for sending emails.
type EmailService interface {
	// SendPasswordResetEmail sends an email with a reset code.
	SendPasswordResetEmail(ctx context.Context, toEmail, resetCode, resetContextInfo string) error
}

// OAuthService handles interactions with the OAuth2 provider
type OAuthService struct {
	userRepo    repository.UserRepository
	cfg         *config.Config
	oAuthConfig *oauth2.Config
	api         string
}

type OAuthProvider interface {
	GetAuthCodeURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	VerifyToken(ctx context.Context, oauth2token *oauth2.Token, tokenProvider string) (*oidc.IDToken, error)
	ProcessUserInfo(ctx context.Context, oauth2token *oauth2.Token, tokenProvider string) (*models.OAuthUser, error)
	ExchangeCodeMobile(ctx context.Context, code, codeVerifier, tokenProvider string) (*oauth2.Token, error)
}
