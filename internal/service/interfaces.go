package service

import (
	"context"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type JWTGenerator interface {
	GenerateToken(authID string) (token string, expiry time.Time, err error)
}

type SessionGenerator interface {
	// VerifySessionToken check if the token is stored in the session store
	VerifySessionToken(ctx context.Context, sessionTokenID string) (*models.VerifyTokenResponse, error)
	ExtendUserSession(ctx context.Context, currentSessionToken string) (*models.ExtendedSessionResponse, error)
	GetUserSessions(ctx context.Context, sessionTokenID string) (*models.GetUserSessionsResponse, error)
	SignOut(ctx context.Context, sessionToken string) error
	SignOutUserSessions(ctx context.Context, authID string, currentSessionTokenToExclude ...string) (int64, error)
}

type SRPAuthGenerator interface {
	// CheckIfUserExists checks if the user email is already in the database
	CheckIfUserExists(ctx context.Context, req models.AuthIDRequest) (bool, error)
	// Register handles user registration
	Register(ctx context.Context, req models.SRPRegisterRequest) error
	// ComputeB handles SRP step 1 (Server -> Client: salt, B)
	ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error)
	// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
	VerifyClientProof(ctx context.Context, req models.AuthStep2Request, hostIP string) (*models.AuthStep3Response, error)
	// InitiatePasswordReset starts the password reset flow for a user.
	InitiatePasswordReset(ctx context.Context, req models.InitiatePasswordResetRequest) error
	// ValidatePasswordResetToken checks if a password reset token is valid without consuming it.
	ValidatePasswordResetToken(ctx context.Context, req models.ValidatePasswordResetTokenRequest) (*models.ValidatePasswordResetTokenResponse, error)
	// CompletePasswordReset completes the password reset flow using a token and new credentials.
	CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error
	// InitiatePasswordChangeVerification starts the process for a logged-in user to change their password by verifying their current one.
	InitiatePasswordChangeVerification(ctx context.Context, authID string) (*models.InitiateChangePasswordResponse, error)
	// ConfirmPasswordChange verifies the user's current password proof and updates to the new password credentials.
	ConfirmPasswordChange(ctx context.Context, authID string, req models.ConfirmChangePasswordRequest) error
	// GenerateCodeAndSendActivationEmail generates an activation code for a new user and sends it via email.
	GenerateCodeAndSendActivationEmail(ctx context.Context, req models.AuthIDRequest) error
	ActivateUser(ctx context.Context, req models.ActivateUserRequest) error
}

// EmailService defines an interface for sending emails.
type EmailService interface {
	// SendPasswordResetEmail sends an email with a reset code.
	SendPasswordResetEmail(ctx context.Context, toEmail, resetCode, resetContextInfo string) error
	SendActivationEmail(ctx context.Context, toEmail, activationCode, appName string) error
}

type UserGenerator interface {
	UpdateUserInfo(ctx context.Context, authID, displayName string) error
	DeleteUser(ctx context.Context, authID string) error
}

type OAuthProvider interface {
	GetAuthCodeURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	VerifyToken(ctx context.Context, oauth2token *oauth2.Token, tokenProvider string) (*oidc.IDToken, error)
	ProcessUserInfo(ctx context.Context, oauth2token *oauth2.Token, tokenProvider string) (*models.OAuthUser, error)
	ExchangeCodeMobile(ctx context.Context, code, codeVerifier, tokenProvider string) (*oauth2.Token, error)
}
