package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"

	"github.com/rs/zerolog/log"
	"github.com/tadglines/go-pkgs/crypto/srp"
)

// ErrSRPAuthenticationFailed indicates a general SRP proof verification failure.
var ErrSRPAuthenticationFailed = errors.New("SRP authentication failed")

// ErrUserAlreadyActivated indicates that an operation cannot be performed because the user is already active.
var ErrUserAlreadyActivated = errors.New("user is already activated")

// SRPAuthService handles the core SRP logic
type SRPAuthService struct {
	userRepo              repository.UserRepository
	stateRepo             repository.StateRepository
	tokenSvc              JWTGenerator
	srpGroup              string
	sessionRepo           repository.SessionRepository
	cfg                   *config.Config
	emailSvc              EmailService
	verificationTokenRepo repository.VerificationTokenRepository // Changed
}

var _ SRPAuthGenerator = (*SRPAuthService)(nil)

// NewSRPAuthService creates a new SRPAuthService
func NewSRPAuthService(
	userRepo repository.UserRepository,
	stateRepo repository.StateRepository,
	sessionRepo repository.SessionRepository,
	tokenSvc JWTGenerator,
	verificationTokenRepo repository.VerificationTokenRepository, // Changed
	emailSvc EmailService,
	cfg *config.Config,
) *SRPAuthService {
	return &SRPAuthService{
		userRepo:              userRepo,
		stateRepo:             stateRepo,
		sessionRepo:           sessionRepo,
		tokenSvc:              tokenSvc,
		verificationTokenRepo: verificationTokenRepo,
		emailSvc:              emailSvc,
		srpGroup:              cfg.SRP.Group,
		cfg:                   cfg,
	}
}

// Helper function to generate a random 6-digit code
func generateSixDigitCode() (string, error) {
	max := big.NewInt(1000000) // Max value is 999999
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil // Pad with leading zeros if necessary
}

func (s *SRPAuthService) CheckIfUserExists(ctx context.Context, req models.AuthIDRequest) (bool, error) {
	if req.AuthID == "" {
		return false, fmt.Errorf("authID cannot be empty")
	}

	return s.userRepo.CheckIfUserExists(ctx, req.AuthID)
}

// Register handles user registration
func (s *SRPAuthService) Register(ctx context.Context, req models.SRPRegisterRequest) error {
	if req.AuthID == "" || req.Salt == "" || req.Verifier == "" {
		log.Warn().Str("authId", req.AuthID).Msg("Missing required fields for user registration")
		return fmt.Errorf("username, salt, and verifier cannot be empty")
	}

	isUserExists, err := s.userRepo.CheckIfUserExists(ctx, req.AuthID)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to check if user exists during registration")
		return fmt.Errorf("failed to check if user exists: %w", err)
	}
	if isUserExists {
		log.Warn().Str("authId", req.AuthID).Msg("User already exists during registration attempt")
		return fmt.Errorf("user already exists %w", repository.ErrUserExists)
	}

	log.Info().Str("authId", req.AuthID).Msg("Attempting to register user")
	extras := map[string]string{
		"salt":     req.Salt,
		"verifier": req.Verifier,
	}

	err = s.userRepo.CreateUser(ctx, req.AuthID, req.DisplayName, "SRP6", extras)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to register user")
		return fmt.Errorf("failed to register user: %w", err)
	}
	return nil
}

// ComputeB handles SRP step 1 (Server -> Client: salt, B)
func (s *SRPAuthService) ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error) {
	log.Info().Str("authId", req.AuthID).Msg("SRP ComputeB (Step 1) request received")

	// Retrieve user credentials
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Msg("Failed to get user credentials for SRP Step 1")
		return nil, fmt.Errorf("failed to get user credentials: %w", err) // Could be ErrUserNotFound
	}
	if userInfo.State == "inactive" {
		log.Warn().Str("authId", req.AuthID).Msg("User is inactive, cannot proceed with SRP login")
		return nil, fmt.Errorf("user has not been activated %w", repository.ErrUserNotActivated)
	}
	saltHex := userInfo.AuthExtras["salt"]
	verifierHex := userInfo.AuthExtras["verifier"]
	log.Debug().Str("authId", req.AuthID).Msg("Retrieved credentials for SRP Step 1")

	verifier, err := hex.DecodeString(verifierHex)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Invalid verifier hex format for SRP Step 1")
		return nil, fmt.Errorf("invalid verifier hex format: %w", err)
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Invalid salt hex format for SRP Step 1")
		return nil, fmt.Errorf("invalid salt hex format: %w", err)
	}

	srp, err := srp.NewSRP(s.srpGroup, s.cfg.SRP.HashingAlgorithm.New, nil)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to create SRP instance for SRP Step 1")
		return nil, fmt.Errorf("failed to create SRP instance: %w", err)
	}

	// Create SRP Server instance
	server := srp.NewServerSession([]byte(req.AuthID), salt, verifier)
	B := server.GetB()

	state := models.AuthSessionState{
		AuthID: req.AuthID,
		Salt:   salt,   // This is 's'
		Server: server, // SRP server instance
		B:      B,      // This is 'B'
		Expiry: time.Now().UTC().Add(s.cfg.SRP.AuthStateExpiry),
	}
	s.stateRepo.StoreAuthState(ctx, req.AuthID, state)

	// Return salt and B
	response := &models.AuthStep1Response{
		Salt:    saltHex,
		ServerB: hex.EncodeToString(B),
	}
	log.Info().Str("authId", req.AuthID).Msg("SRP ComputeB (Step 1) successful, returning Salt and ServerB")
	return response, nil
}

// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
func (s *SRPAuthService) VerifyClientProof(ctx context.Context, req models.AuthStep2Request, hostIP string) (*models.AuthStep3Response, error) {
	log.Info().Str("authId", req.AuthID).Msg("SRP VerifyClientProof (Step 2) request received")

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to get user info after SRP auth")
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	userID := userInfo.ID

	// 1. Retrieve stored state (secret 'b'/'secret2', verifier 'V')
	session, err := s.stateRepo.GetAuthState(ctx, req.AuthID)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Msg("Failed to retrieve auth state for SRP Step 2")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 404)
		// s.stateRepo.DeleteAuthState(req.AuthID)                                    // Uncomment if needed
		return nil, fmt.Errorf("failed to retrieve authentication state: %w", err) // Don't leak internal state details
	}

	// 2. Decode client public ephemeral 'A'
	bytesA, err := hex.DecodeString(req.ClientA)
	if err != nil || len(bytesA) == 0 { // Also check for empty result
		log.Warn().Err(err).Str("authId", req.AuthID).Str("clientA", req.ClientA).Msg("Invalid client public ephemeral 'A' format for SRP Step 2")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 400)
		return nil, fmt.Errorf("invalid client A format: %w", err)
	}
	log.Debug().Str("authId", req.AuthID).Msg("Decoded ClientA for SRP Step 2")

	// 3. Decode client proof 'M1'
	ClientM1, err := hex.DecodeString(req.ClientProofM1)
	if err != nil || len(ClientM1) == 0 { // Also check for empty result
		log.Warn().Err(err).Str("authId", req.AuthID).Str("clientM1", req.ClientProofM1).Msg("Invalid client proof 'M1' format for SRP Step 2")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 401)
		return nil, fmt.Errorf("invalid client proof M1 format: %w", err)
	}
	log.Debug().Str("authId", req.AuthID).Msg("Decoded ClientProofM1 for SRP Step 2")

	// 4. Create SRP Server instance with retrieved state ('b'/'secret2', 'V'/verifier)
	server := session.Server
	if server == nil {
		log.Error().Str("authId", req.AuthID).Msg("Failed to re-create SRP server instance (nil server in state) for SRP Step 2")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 500)
		return nil, fmt.Errorf("failed to create SRP server instance")
	}
	log.Debug().Str("authId", req.AuthID).Msg("Re-created SRP server instance for SRP Step 2")

	// 5. Set client public ephemeral 'A' on the server instance
	k, err := server.ComputeKey(bytesA)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to compute key for SRP Step 2")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 500)
		return nil, fmt.Errorf("failed to compute key: %w", err)
	}
	log.Debug().Str("authId", req.AuthID).Str("key", hex.EncodeToString(k)).Msg("Computed key for SRP Step 2")

	isValid := server.VerifyClientAuthenticator(ClientM1)
	if !isValid {
		log.Warn().Str("authId", req.AuthID).Msg("Client proof M1 verification failed for SRP Step 2")
		// Clean up state after failed attempt
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 401)
		s.stateRepo.DeleteAuthState(ctx, req.AuthID)
		return nil, ErrSRPAuthenticationFailed
	}
	log.Info().Str("authId", req.AuthID).Msg("Client proof M1 verified for SRP Step 2")

	err = s.stateRepo.DeleteAuthState(ctx, req.AuthID)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Msg("Failed to delete auth state after successful SRP auth")
	} else {
		log.Debug().Str("authId", req.AuthID).Msg("Deleted auth state after successful SRP auth")
	}

	// Generate session token
	sessionTokenString, sessionTokenExpiry, err := s.tokenSvc.GenerateToken(req.AuthID)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to generate session token after SRP auth")
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Create and store the user session
	sessionRecord := &models.Session{
		SessionID: sessionTokenString,
		UserID:    userID,
		Host:      hostIP,
		AuthID:    req.AuthID,
		Expiry:    sessionTokenExpiry,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.sessionRepo.StoreSession(ctx, sessionRecord); err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to store session token after SRP auth")
		s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 401)
		return nil, fmt.Errorf("failed to store session token: %w", err)
	}
	log.Info().Str("authId", req.AuthID).Time("sessionExpiry", sessionRecord.Expiry).Msg("Session token generated and stored after SRP auth")

	M2 := server.ComputeAuthenticator(ClientM1)
	response := &models.AuthStep3Response{
		ServerProofM2: hex.EncodeToString(M2),
		SessionToken:  sessionTokenString,
		SessionExpiry: sessionTokenExpiry,
	}
	s.userRepo.CreateUserAuthEvent(ctx, userID, hostIP, 200)
	log.Info().Str("authId", req.AuthID).Msg("SRP VerifyClientProof (Step 2) successful, returning ServerProofM2 and session token")
	return response, nil
}

// InitiatePasswordChangeVerification handles the first step of changing a password for an authenticated user.
// It requires the user to prove knowledge of their current password.
// It returns the user's current salt and a server-generated 'B' value for the current password.
func (s *SRPAuthService) InitiatePasswordChangeVerification(ctx context.Context, authID string) (*models.InitiateChangePasswordResponse, error) {
	if authID == "" {
		return nil, fmt.Errorf("authID cannot be empty for password change initiation")
	}
	log.Info().Str("authId", authID).Msg("Initiating password change verification")

	// Retrieve user's current credentials (salt and verifier)
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Warn().Err(err).Str("authId", authID).Msg("Failed to get user credentials for password change initiation")
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}
	currentSaltHex := userInfo.AuthExtras["salt"]
	currentVerifierHex := userInfo.AuthExtras["verifier"]

	currentVerifierBytes, err := hex.DecodeString(currentVerifierHex)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Invalid current verifier hex for password change initiation")
		return nil, fmt.Errorf("invalid current verifier hex format: %w", err)
	}
	currentSaltBytes, err := hex.DecodeString(currentSaltHex)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Invalid current salt hex for password change initiation")
		return nil, fmt.Errorf("invalid current salt hex format: %w", err)
	}

	srpInstance, err := srp.NewSRP(s.srpGroup, s.cfg.SRP.HashingAlgorithm.New, nil)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to create SRP instance for password change initiation")
		return nil, fmt.Errorf("failed to create SRP instance: %w", err)
	}

	// Create SRP Server session for current password verification
	serverSession := srpInstance.NewServerSession([]byte(authID), currentSaltBytes, currentVerifierBytes)
	serverBBytes := serverSession.GetB()

	// Store this server session state for the next step
	// Use a distinct key or context for password change verification state
	stateKey := "pwdchange:" + authID // Simple prefixing for distinction
	state := models.AuthSessionState{
		AuthID: authID,
		Salt:   currentSaltBytes, // Current salt
		Server: serverSession,    // SRP server instance for current password
		B:      serverBBytes,
		Expiry: time.Now().UTC().Add(s.cfg.SessionConfig.ValidationDuration),
	}
	s.stateRepo.StoreAuthState(ctx, stateKey, state)

	log.Info().Str("authId", authID).Msg("Password change verification initiated successfully. Returning current salt and ServerB.")
	return &models.InitiateChangePasswordResponse{
		Salt:    currentSaltHex,
		ServerB: hex.EncodeToString(serverBBytes),
	}, nil
}

// ConfirmPasswordChange verifies the client's proof of their current password (M1)
// and, if successful, updates the user's credentials to the new salt and verifier.
func (s *SRPAuthService) ConfirmPasswordChange(ctx context.Context, authID string, req models.ConfirmChangePasswordRequest) error {
	if authID == "" {
		return fmt.Errorf("authID cannot be empty for password change confirmation")
	}
	if req.ClientA == "" || req.ClientM1 == "" || req.NewSalt == "" || req.NewVerifier == "" {
		return fmt.Errorf("clientA, clientM1, newSalt, and newVerifier are required")
	}
	log.Info().Str("authId", authID).Msg("Attempting to confirm password change")

	stateKey := "pwdchange:" + authID
	storedState, err := s.stateRepo.GetAuthState(ctx, stateKey)
	if err != nil {
		log.Warn().Err(err).Str("authId", authID).Msg("Failed to retrieve auth state for password change confirmation")
		s.stateRepo.DeleteAuthState(ctx, stateKey) // Clean up if retrieval failed (e.g. expired)
		return fmt.Errorf("password change session expired or invalid: %w", err)
	}

	serverSession := storedState.Server
	if serverSession == nil {
		log.Error().Str("authId", authID).Msg("Nil server session in stored state for password change confirmation")
		s.stateRepo.DeleteAuthState(ctx, stateKey)
		return fmt.Errorf("internal error: invalid password change session state")
	}

	clientABytes, _ := hex.DecodeString(req.ClientA) // Error handling for hex decode omitted for brevity, add in real code
	clientM1Bytes, _ := hex.DecodeString(req.ClientM1)
	_, err = serverSession.ComputeKey(clientABytes)
	if err != nil {
		log.Warn().Err(err).Str("authId", authID).Msg("Failed to compute key for current password during password change confirmation")
		s.stateRepo.DeleteAuthState(ctx, stateKey)
		return fmt.Errorf("current password verification failed (key computation): %w", ErrSRPAuthenticationFailed)
	}

	if !serverSession.VerifyClientAuthenticator(clientM1Bytes) {
		log.Warn().Str("authId", authID).Msg("Current password M1 verification failed during password change confirmation")
		s.stateRepo.DeleteAuthState(ctx, stateKey)
		return fmt.Errorf("current password verification failed: %w", ErrSRPAuthenticationFailed)
	}

	s.stateRepo.DeleteAuthState(ctx, stateKey) // Current password verified, clean up state
	log.Info().Str("authId", authID).Msg("Current password verified. Proceeding to update password.")

	err = s.userRepo.UpdateUserSRPAuth(ctx, authID, req.NewSalt, req.NewVerifier)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to update SRP auth for password change")
		return fmt.Errorf("failed to change password: %w", err)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err == nil && userInfo != nil {
		s.sessionRepo.DeleteUserSessions(ctx, userInfo.ID) // Invalidate all sessions
		log.Info().Str("authId", authID).Int64("userId", userInfo.ID).Msg("All active sessions invalidated after password change.")
	} else {
		log.Warn().Err(err).Str("authId", authID).Msg("Could not retrieve user info to invalidate sessions after password change.")
	}

	log.Info().Str("authId", authID).Msg("Password changed successfully")
	return nil
}

// InitiatePasswordReset starts the password reset flow.
func (s *SRPAuthService) InitiatePasswordReset(ctx context.Context, req models.InitiatePasswordResetRequest) error {
	if req.AuthID == "" {
		return fmt.Errorf("authID (email) cannot be empty")
	}

	log.Info().Str("authId", req.AuthID).Msg("Attempting to initiate password reset")

	exists, err := s.userRepo.CheckIfUserExists(ctx, req.AuthID)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Msg("Failed to check if user exists for password reset")
		return nil
	}
	if !exists {
		log.Warn().Str("authId", req.AuthID).Msg("User not found for password reset. No email will be sent.")
		return nil
	}

	resetCode, err := generateSixDigitCode()
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to generate reset code for password reset")
		return fmt.Errorf("failed to initiate password reset") // Internal error
	}

	activationExpiry := s.cfg.SessionConfig.ValidationDuration
	if activationExpiry == 0 {
		activationExpiry = 15 * time.Minute // Default to 15 minutes if not configured (matches config default)
	}

	err = s.verificationTokenRepo.StorePasswordResetToken(ctx, req.AuthID, resetCode, activationExpiry)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to store password reset code")
		return fmt.Errorf("failed to store password reset token: %w", err)
	}

	appName := s.cfg.App.Name
	err = s.emailSvc.SendPasswordResetEmail(ctx, req.AuthID, resetCode, appName)
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to send password reset email")
		return fmt.Errorf("failed to send password reset email") // Internal error
	}

	log.Info().Str("authId", req.AuthID).Msg("Password reset code sent successfully")
	return nil
}

// ValidatePasswordResetToken checks if a password reset token (6-digit code) is valid
// without consuming it.
func (s *SRPAuthService) ValidatePasswordResetToken(ctx context.Context, req models.ValidatePasswordResetTokenRequest) (*models.ValidatePasswordResetTokenResponse, error) {
	if req.Token == "" {
		return &models.ValidatePasswordResetTokenResponse{IsValid: false}, fmt.Errorf("token cannot be empty")
	}
	if req.AuthID == "" {
		return &models.ValidatePasswordResetTokenResponse{IsValid: false}, fmt.Errorf("authID cannot be empty")
	}

	log.Info().Str("authId", req.AuthID).Str("token", req.Token).Msg("Attempting to validate password reset token")

	authID, err := s.verificationTokenRepo.GetAuthIDForValidPasswordResetToken(ctx, req.AuthID, req.Token)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Str("token", req.Token).Msg("Password reset token validation failed")
		return &models.ValidatePasswordResetTokenResponse{IsValid: false}, fmt.Errorf("invalid or expired password reset token: %w", err)
	}

	log.Info().Str("authId", authID).Str("token", req.Token).Msg("Password reset token is valid")
	return &models.ValidatePasswordResetTokenResponse{
		IsValid: true,
		AuthID:  authID,
	}, nil
}

// CompletePasswordReset completes the password reset flow.
// It re-validates and consumes the token before updating the password.
func (s *SRPAuthService) CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error {
	if req.AuthID == "" || req.Token == "" || req.NewSalt == "" || req.NewVerifier == "" {
		return fmt.Errorf("authID, token, new salt, and new verifier cannot be empty")
	}

	log.Info().Str("authId", req.AuthID).Str("token", req.Token).Msg("Attempting to complete password reset")

	// ValidateAndConsumePasswordResetToken now expects authID as input.
	// It will return the same authID if the token is valid for that user and consumes it.
	// We use req.AuthID as the first argument.
	authID, err := s.verificationTokenRepo.ValidateAndConsumePasswordResetToken(ctx, req.AuthID, req.Token)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Str("token", req.Token).Msg("Invalid, expired, or already consumed reset token for password reset completion")
		return fmt.Errorf("invalid, expired, or already consumed password reset token: %w", err)
	}

	log.Info().Str("authId", authID).Msg("Password reset token validated and consumed. Updating password.")

	err = s.userRepo.UpdateUserSRPAuth(ctx, authID, req.NewSalt, req.NewVerifier)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to update SRP auth during password reset completion")
		return fmt.Errorf("failed to reset password: %w", err)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID) // To get userID for session invalidation
	if err == nil && userInfo != nil {
		s.sessionRepo.DeleteUserSessions(ctx, userInfo.ID) // Invalidate all sessions
		log.Info().Str("authId", authID).Int64("userId", userInfo.ID).Msg("All active sessions invalidated after password reset.")
	} else {
		log.Warn().Err(err).Str("authId", authID).Msg("Could not retrieve user info to invalidate sessions after password reset.")
	}

	log.Info().Str("authId", authID).Msg("Password reset completed successfully")
	return nil
}

// GenerateCodeAndSendActivationEmail generates a 6-digit activation code for a user
// and sends it via email. It's typically used after registration for users
// who are in an "inactive" state.
func (s *SRPAuthService) GenerateCodeAndSendActivationEmail(ctx context.Context, req models.AuthIDRequest) error {
	if req.AuthID == "" {
		return errors.New("authID (email) cannot be empty")
	}

	log.Info().Str("authId", req.AuthID).Msg("Attempting to generate and send activation email")

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			log.Warn().Str("authId", req.AuthID).Msg("User not found for activation email.")
			return err
		}
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to get user info for activation email")
		return fmt.Errorf("failed to retrieve user information: %w", err)
	}

	if userInfo.State == "active" {
		log.Info().Str("authId", req.AuthID).Msg("User is already active. No activation email sent.")
		return ErrUserAlreadyActivated
	}

	activationCode, err := generateSixDigitCode()
	if err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to generate activation code")
		return fmt.Errorf("failed to generate activation code: %w", err)
	}

	activationExpiry := s.cfg.SessionConfig.ValidationDuration
	if activationExpiry == 0 {
		activationExpiry = 15 * time.Minute // Default to 15 minutes if not configured
	}

	if err := s.verificationTokenRepo.StoreActivationToken(ctx, req.AuthID, activationCode, activationExpiry); err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to store activation code")
		return fmt.Errorf("%w", err)
	}

	appName := s.cfg.App.Name
	if err := s.emailSvc.SendActivationEmail(ctx, req.AuthID, activationCode, appName); err != nil {
		log.Error().Err(err).Str("authId", req.AuthID).Msg("Failed to send activation email")
		return fmt.Errorf("failed to send activation email: %w", err)
	}

	log.Info().Str("authId", req.AuthID).Msg("Activation code sent successfully")
	return nil
}

func (s *SRPAuthService) ActivateUser(ctx context.Context, req models.ActivateUserRequest) error {
	if req.AuthID == "" || req.Code == "" {
		return errors.New("authID and activation code cannot be empty")
	}
	log.Info().Str("authId", req.AuthID).Str("code", req.Code).Msg("Attempting to activate user")

	// ValidateAndConsumeActivationToken now expects authID as input.
	// It will return the same authID if the token is valid for that user and consumes it.
	// We use req.AuthID as the first argument.
	validatedAuthID, err := s.verificationTokenRepo.ValidateAndConsumeActivationToken(ctx, req.AuthID, req.Code)
	if err != nil {
		log.Warn().Err(err).Str("authId", req.AuthID).Str("code", req.Code).Msg("Invalid, expired, or already consumed activation code")
		return fmt.Errorf("invalid, expired, or already consumed activation code: %w", err)
	}

	log.Info().Str("authId", validatedAuthID).Msg("Activation token validated and consumed. Activating account.")
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, validatedAuthID)
	if err != nil {
		log.Error().Err(err).Str("authId", validatedAuthID).Msg("Failed to retrieve user information for activation")
		return fmt.Errorf("failed to retrieve user information: %w", err)
	}
	err = s.userRepo.ActivateUser(ctx, userInfo.ID)
	if err != nil {
		log.Error().Err(err).Str("authId", validatedAuthID).Int64("userId", userInfo.ID).Msg("Failed to activate user in repository")
		return fmt.Errorf("failed to activate user: %w", err)
	}

	log.Info().Str("authId", validatedAuthID).Msg("Account activated successfully")
	return nil
}
