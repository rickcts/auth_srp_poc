package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"

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
		verificationTokenRepo: verificationTokenRepo, // Changed
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
		log.Printf("[AuthService.Register] ERROR: Missing required fields for user '%s'", req.AuthID)
		return fmt.Errorf("username, salt, and verifier cannot be empty")
	}

	isUserExists, err := s.userRepo.CheckIfUserExists(ctx, req.AuthID)
	if err != nil {
		log.Printf("[AuthService.Register] ERROR: Failed to check if user '%s' exists: %v", req.AuthID, err)
		return fmt.Errorf("failed to check if user exists: %w", err)
	}
	if isUserExists {
		log.Printf("[AuthService.Register] ERROR: User '%s' already exists", req.AuthID)
		return fmt.Errorf("user already exists %w", repository.ErrUserExists)
	}

	log.Printf("[AuthService.Register] Attempting to register user '%s' with Salt: %s, Verifier: %s", req.AuthID, req.Salt, req.Verifier)
	extras := map[string]string{
		"salt":     req.Salt,
		"verifier": req.Verifier,
	}

	err = s.userRepo.CreateUser(ctx, req.AuthID, req.DisplayName, "SRP6", extras)
	if err != nil {
		log.Printf("[AuthService.Register] ERROR: Failed to register user '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to register user: %w", err)
	}
	log.Printf("[AuthService.Register] SUCCESS: User registered: %s", req.AuthID)
	return nil
}

// ComputeB handles SRP step 1 (Server -> Client: salt, B)
func (s *SRPAuthService) ComputeB(ctx context.Context, req models.AuthStep1Request) (*models.AuthStep1Response, error) {
	log.Printf("[AuthService.ComputeB] Received Step 1 request for user '%s'", req.AuthID)

	// Retrieve user credentials
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Failed to get credentials for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to get user credentials: %w", err) // Could be ErrUserNotFound
	}
	if userInfo.State == "inactive" {
		log.Printf("[AuthService.ComputeB] ERROR: User '%s' is inactive", req.AuthID)
		return nil, fmt.Errorf("user has not been activated %w", repository.ErrUserNotActivated)
	}
	saltHex := userInfo.AuthExtras["salt"]
	verifierHex := userInfo.AuthExtras["verifier"]
	log.Printf("[AuthService.ComputeB] Retrieved credentials for user '%s': Salt=%s, Verifier=%s", req.AuthID, saltHex, verifierHex)

	verifier, err := hex.DecodeString(verifierHex)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Invalid verifier hex format for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("invalid verifier hex format: %w", err)
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Invalid salt hex format for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("invalid salt hex format: %w", err)
	}

	srp, err := srp.NewSRP(s.srpGroup, s.cfg.SRP.HashingAlgorithm.New, nil)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Failed to create SRP instance for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to create SRP instance: %w", err)
	}

	// Create SRP Server instance
	server := srp.NewServerSession([]byte(req.AuthID), salt, verifier)
	B := server.GetB()

	state := models.AuthSessionState{
		AuthID: req.AuthID,
		Salt:   salt,                      // This is 's'
		Server: server,                    // SRP server instance
		B:      B,                         // This is 'B'
		Expiry: s.cfg.SRP.AuthStateExpiry, // time.Time
	}
	s.stateRepo.StoreAuthState(req.AuthID, state) // Assuming StoreAuthState handles expiry correctly

	// Return salt and B
	response := &models.AuthStep1Response{
		Salt:    saltHex,
		ServerB: hex.EncodeToString(B),
	}
	log.Printf("[AuthService.ComputeB] Returning Salt and ServerB for user '%s'", req.AuthID)
	return response, nil
}

// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
func (s *SRPAuthService) VerifyClientProof(ctx context.Context, req models.AuthStep2Request) (*models.AuthStep3Response, error) {
	log.Printf("[AuthService.VerifyClientProof] Received Step 2 request for user '%s': ClientA=%s, ClientProofM1=%s",
		req.AuthID, req.ClientA, req.ClientProofM1)

	// 1. Retrieve stored state (secret 'b'/'secret2', verifier 'V')
	session, err := s.stateRepo.GetAuthState(req.AuthID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to retrieve auth state for user '%s': %v", req.AuthID, err)
		// s.stateRepo.DeleteAuthState(req.AuthID)                                    // Uncomment if needed
		return nil, fmt.Errorf("failed to retrieve authentication state: %w", err) // Don't leak internal state details
	}

	// 2. Decode client public ephemeral 'A'
	bytesA, err := hex.DecodeString(req.ClientA)
	if err != nil || len(bytesA) == 0 { // Also check for empty result
		log.Printf("[AuthService.VerifyClientProof] ERROR: InvalID client public ephemeral 'A' format for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("invalid client A format: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Decoded ClientA for user '%s': %s", req.AuthID, hex.EncodeToString(bytesA))

	// 3. Decode client proof 'M1'
	ClientM1, err := hex.DecodeString(req.ClientProofM1)
	if err != nil || len(ClientM1) == 0 { // Also check for empty result
		log.Printf("[AuthService.VerifyClientProof] ERROR: InvalID client proof 'M1' format for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("invalid client proof M1 format: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Decoded ClientProofM1 for user '%s': %s", req.AuthID, hex.EncodeToString(ClientM1))

	// 4. Create SRP Server instance with retrieved state ('b'/'secret2', 'V'/verifier)
	server := session.Server
	if server == nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to re-create SRP server instance for user '%s'", req.AuthID)
		return nil, fmt.Errorf("failed to create SRP server instance")
	}
	log.Printf("[AuthService.VerifyClientProof] Re-created SRP server instance for user '%s'", req.AuthID)

	// 5. Set client public ephemeral 'A' on the server instance
	k, err := server.ComputeKey(bytesA)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to compute key for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to compute key: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Computed key for user '%s': %s", req.AuthID, hex.EncodeToString(k))

	log.Printf("[AuthService.VerifyClientProof] Set ClientA on SRP server for user '%s'", req.AuthID)
	isValID := server.VerifyClientAuthenticator(ClientM1)
	if !isValID {
		// This means the client's M1 dID not match the server's calculation! Authentication fails.
		log.Printf("[AuthService.VerifyClientProof] ERROR: Client proof M1 verification failed for user '%s': %v", req.AuthID, err)
		// Security ConsIDeration: AvoID leaking *why* it failed if possible in production error messages.
		// Clean up state after failed attempt
		s.stateRepo.DeleteAuthState(req.AuthID)                       // Add Delete method to repo if needed
		return nil, fmt.Errorf("client proof M1 verification failed") // Generic error to client
	}
	// M1 verification successful!
	log.Printf("[AuthService.VerifyClientProof] SUCCESS: Client proof M1 verified for user '%s'", req.AuthID)

	err = s.stateRepo.DeleteAuthState(req.AuthID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] WARN: Failed to delete auth state for user '%s' after successful auth: %v", req.AuthID, err)
	} else {
		log.Printf("[AuthService.VerifyClientProof] Deleted auth state for user '%s' after successful auth.", req.AuthID)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to get user info for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	authID := userInfo.AuthID

	// Generate session token
	sessionTokenString, sessionTokenExpiry, err := s.tokenSvc.GenerateToken(req.AuthID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to generate session token for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Create and store the user session
	sessionRecord := &models.Session{
		SessionID: sessionTokenString,
		UserID:    userInfo.ID,
		AuthID:    authID,
		Expiry:    sessionTokenExpiry,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.sessionRepo.StoreSession(ctx, sessionRecord); err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to store session token for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to store session token: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] SUCCESS: Session token generated and stored for user '%s'. Session Expiry: %v", req.AuthID, sessionRecord.Expiry)

	M2 := server.ComputeAuthenticator(ClientM1)
	response := &models.AuthStep3Response{
		ServerProofM2: hex.EncodeToString(M2),
		SessionToken:  sessionTokenString,
		SessionExpiry: sessionTokenExpiry,
	}
	log.Printf("[AuthService.VerifyClientProof] Returning ServerProofM2 for user '%s'", req.AuthID)
	return response, nil
}

// InitiatePasswordChangeVerification handles the first step of changing a password for an authenticated user.
// It requires the user to prove knowledge of their current password.
// It returns the user's current salt and a server-generated 'B' value for the current password.
func (s *SRPAuthService) InitiatePasswordChangeVerification(ctx context.Context, authID string) (*models.InitiateChangePasswordResponse, error) {
	if authID == "" {
		return nil, fmt.Errorf("authID cannot be empty for password change initiation")
	}
	log.Printf("[AuthService.InitiatePasswordChangeVerification] Initiating for user '%s'", authID)

	// Retrieve user's current credentials (salt and verifier)
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordChangeVerification] ERROR: Failed to get credentials for user '%s': %v", authID, err)
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}
	currentSaltHex := userInfo.AuthExtras["salt"]
	currentVerifierHex := userInfo.AuthExtras["verifier"]

	currentVerifierBytes, err := hex.DecodeString(currentVerifierHex)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordChangeVerification] ERROR: Invalid current verifier hex for user '%s': %v", authID, err)
		return nil, fmt.Errorf("invalid current verifier hex format: %w", err)
	}
	currentSaltBytes, err := hex.DecodeString(currentSaltHex)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordChangeVerification] ERROR: Invalid current salt hex for user '%s': %v", authID, err)
		return nil, fmt.Errorf("invalid current salt hex format: %w", err)
	}

	srpInstance, err := srp.NewSRP(s.srpGroup, s.cfg.SRP.HashingAlgorithm.New, nil)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordChangeVerification] ERROR: Failed to create SRP instance for user '%s': %v", authID, err)
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
		Expiry: time.Now().Add(s.cfg.Security.PasswordResetTokenExpiry), // Reuse or define a new config for this expiry
	}
	s.stateRepo.StoreAuthState(stateKey, state)

	log.Printf("[AuthService.InitiatePasswordChangeVerification] SUCCESS for user '%s'. Returning current salt and ServerB.", authID)
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
	log.Printf("[AuthService.ConfirmPasswordChange] Attempting for user '%s'", authID)

	stateKey := "pwdchange:" + authID
	storedState, err := s.stateRepo.GetAuthState(stateKey)
	if err != nil {
		log.Printf("[AuthService.ConfirmPasswordChange] ERROR: Failed to retrieve auth state for user '%s': %v", authID, err)
		s.stateRepo.DeleteAuthState(stateKey) // Clean up if retrieval failed (e.g. expired)
		return fmt.Errorf("password change session expired or invalid: %w", err)
	}

	serverSession := storedState.Server
	if serverSession == nil {
		log.Printf("[AuthService.ConfirmPasswordChange] ERROR: Nil server session in stored state for user '%s'", authID)
		s.stateRepo.DeleteAuthState(stateKey)
		return fmt.Errorf("internal error: invalid password change session state")
	}

	clientABytes, _ := hex.DecodeString(req.ClientA) // Error handling for hex decode omitted for brevity, add in real code
	clientM1Bytes, _ := hex.DecodeString(req.ClientM1)

	_, err = serverSession.ComputeKey(clientABytes)
	if err != nil {
		log.Printf("[AuthService.ConfirmPasswordChange] ERROR: Failed to compute key for current password for user '%s': %v", authID, err)
		s.stateRepo.DeleteAuthState(stateKey)
		return fmt.Errorf("current password verification failed (key computation): %w", ErrSRPAuthenticationFailed)
	}

	if !serverSession.VerifyClientAuthenticator(clientM1Bytes) {
		log.Printf("[AuthService.ConfirmPasswordChange] ERROR: Current password M1 verification failed for user '%s'", authID)
		s.stateRepo.DeleteAuthState(stateKey)
		return fmt.Errorf("current password verification failed: %w", ErrSRPAuthenticationFailed)
	}

	s.stateRepo.DeleteAuthState(stateKey) // Current password verified, clean up state
	log.Printf("[AuthService.ConfirmPasswordChange] Current password verified for user '%s'. Proceeding to update password.", authID)

	err = s.userRepo.UpdateUserSRPAuth(ctx, authID, req.NewSalt, req.NewVerifier)
	if err != nil {
		log.Printf("[AuthService.ConfirmPasswordChange] ERROR: Failed to update SRP auth for user '%s': %v", authID, err)
		return fmt.Errorf("failed to change password: %w", err)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err == nil && userInfo != nil {
		s.sessionRepo.DeleteUserSessions(ctx, userInfo.ID, "") // Invalidate all sessions
		log.Printf("[AuthService.ConfirmPasswordChange] All active sessions for user '%s' (ID: %d) have been invalidated.", authID, userInfo.ID)
	} else {
		log.Printf("[AuthService.ConfirmPasswordChange] WARN: Could not retrieve user info for '%s' to invalidate sessions: %v", authID, err)
	}

	log.Printf("[AuthService.ConfirmPasswordChange] SUCCESS: Password changed for user '%s'", authID)
	return nil
}

// InitiatePasswordReset starts the password reset flow.
func (s *SRPAuthService) InitiatePasswordReset(ctx context.Context, req models.InitiatePasswordResetRequest) error {
	if req.AuthID == "" {
		return fmt.Errorf("authID (email) cannot be empty")
	}

	log.Printf("[AuthService.InitiatePasswordReset] Attempting to initiate password reset for authID '%s'", req.AuthID)

	exists, err := s.userRepo.CheckIfUserExists(ctx, req.AuthID)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to check if user '%s' exists: %v", req.AuthID, err)
		// Do not reveal if user exists or not to prevent account enumeration.
		// Log the error internally but return a generic success-like response to the client.
		return nil // Or a specific error that the handler interprets as "email sent if user exists"
	}
	if !exists {
		log.Printf("[AuthService.InitiatePasswordReset] User '%s' not found. No reset email will be sent.", req.AuthID)
		return nil // Same as above, generic response.
	}

	resetCode, err := generateSixDigitCode()
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to generate reset code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to initiate password reset") // Internal error
	}

	// Ensure PasswordResetTokenExpiry is configured, e.g., 15 minutes
	expiry := time.Now().UTC().Add(s.cfg.Security.PasswordResetTokenExpiry)

	err = s.verificationTokenRepo.StorePasswordResetToken(ctx, req.AuthID, resetCode, expiry)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to store password reset code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to initiate password reset") // Internal error
	}

	appName := "Your Application"
	err = s.emailSvc.SendPasswordResetEmail(ctx, req.AuthID, resetCode, appName)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to send password reset email to '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to send password reset email") // Internal error
	}

	log.Printf("[AuthService.InitiatePasswordReset] SUCCESS: Password reset code sent for '%s'", req.AuthID)
	return nil
}

// ValidatePasswordResetToken checks if a password reset token (6-digit code) is valid
// without consuming it.
func (s *SRPAuthService) ValidatePasswordResetToken(ctx context.Context, req models.ValidatePasswordResetTokenRequest) (*models.ValidatePasswordResetTokenResponse, error) {
	if req.Token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	log.Printf("[AuthService.ValidatePasswordResetToken] Attempting to validate reset token: %s", req.Token)

	authID, err := s.verificationTokenRepo.GetAuthIDForValidPasswordResetToken(ctx, req.Token)
	if err != nil {
		log.Printf("[AuthService.ValidatePasswordResetToken] Validation failed for token '%s': %v", req.Token, err)
		return &models.ValidatePasswordResetTokenResponse{IsValid: false}, fmt.Errorf("invalid or expired password reset token: %w", err)
	}

	log.Printf("[AuthService.ValidatePasswordResetToken] SUCCESS: Token '%s' is valid for authID '%s'", req.Token, authID)
	return &models.ValidatePasswordResetTokenResponse{
		IsValid: true,
		AuthID:  authID,
	}, nil
}

// CompletePasswordReset completes the password reset flow.
// It re-validates and consumes the token before updating the password.
func (s *SRPAuthService) CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error {
	if req.Token == "" || req.NewSalt == "" || req.NewVerifier == "" {
		return fmt.Errorf("token, new salt, and new verifier cannot be empty")
	}

	log.Printf("[AuthService.CompletePasswordReset] Attempting to complete password reset with code: %s", req.Token)

	authID, err := s.verificationTokenRepo.ValidateAndConsumePasswordResetToken(ctx, req.Token)
	if err != nil {
		log.Printf("[AuthService.CompletePasswordReset] ERROR: Invalid, expired, or already consumed reset token '%s': %v", req.Token, err)
		return fmt.Errorf("invalid, expired, or already consumed password reset token: %w", err)
	}

	log.Printf("[AuthService.CompletePasswordReset] Token validated and consumed for authID '%s'. Updating password.", authID)

	err = s.userRepo.UpdateUserSRPAuth(ctx, authID, req.NewSalt, req.NewVerifier)
	if err != nil {
		log.Printf("[AuthService.CompletePasswordReset] ERROR: Failed to update SRP auth for user '%s': %v", authID, err)
		return fmt.Errorf("failed to reset password: %w", err)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID) // To get userID for session invalidation
	if err == nil && userInfo != nil {
		s.sessionRepo.DeleteUserSessions(ctx, userInfo.ID) // Invalidate all sessions
		log.Printf("[AuthService.CompletePasswordReset] All active sessions for user '%s' (ID: %d) have been invalidated.", authID, userInfo.ID)
	} else {
		log.Printf("[AuthService.CompletePasswordReset] WARN: Could not retrieve user info for '%s' to invalidate sessions: %v", authID, err)
	}

	log.Printf("[AuthService.CompletePasswordReset] SUCCESS: Password reset for user '%s'", authID)
	return nil
}

// GenerateCodeAndSendActivationEmail generates a 6-digit activation code for a user
// and sends it via email. It's typically used after registration for users
// who are in an "inactive" state.
func (s *SRPAuthService) GenerateCodeAndSendActivationEmail(ctx context.Context, req models.AuthIDRequest) error {
	if req.AuthID == "" {
		return errors.New("authID (email) cannot be empty")
	}

	log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] Attempting for authID '%s'", req.AuthID)

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] User '%s' not found.", req.AuthID)
			return err
		}
		log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] ERROR: Failed to get user info for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to retrieve user information: %w", err)
	}

	if userInfo.State == "active" {
		log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] User '%s' is already active.", req.AuthID)
		return ErrUserAlreadyActivated
	}

	activationCode, err := generateSixDigitCode()
	if err != nil {
		log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] ERROR: Failed to generate activation code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to generate activation code: %w", err)
	}

	activationExpiry := s.cfg.Security.PasswordResetTokenExpiry
	if activationExpiry == 0 {
		activationExpiry = 15 * time.Minute // Default to 15 minutes if not configured
	}
	expiry := time.Now().UTC().Add(activationExpiry)

	if err := s.verificationTokenRepo.StoreActivationToken(ctx, req.AuthID, activationCode, expiry); err != nil {
		log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] ERROR: Failed to store activation code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to store activation code: %w", err)
	}

	appName := "Your Application" // Assuming AppName is available in config
	if err := s.emailSvc.SendActivationEmail(ctx, req.AuthID, activationCode, appName); err != nil {
		log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] ERROR: Failed to send activation email to '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to send activation email: %w", err)
	}

	log.Printf("[AuthService.GenerateCodeAndSendActivationEmail] SUCCESS: Activation code sent for '%s'", req.AuthID)
	return nil
}

func (s *SRPAuthService) ActivateUser(ctx context.Context, req models.ActivateUserRequest) error {
	if req.AuthID == "" || req.Code == "" {
		return errors.New("authID and activation code cannot be empty")
	}
	log.Printf("[AuthService.ActivateAccount] Attempting to activate user '%s' with code: %s", req.AuthID, req.Code)

	authID, err := s.verificationTokenRepo.ValidateAndConsumeActivationToken(ctx, req.Code)
	if err != nil {
		log.Printf("[AuthService.ActivateAccount] ERROR: Invalid, expired, or already consumed activation code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("invalid, expired, or already consumed activation code: %w", err)
	}

	log.Printf("[AuthService.ActivateAccount] Token validated and consumed for authID '%s'. Activating account.", authID)
	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Printf("[AuthService.ActivateAccount] ERROR: Failed to get user info for '%s': %v", authID, err)
		return fmt.Errorf("failed to retrieve user information: %w", err)
	}
	err = s.userRepo.ActivateUser(ctx, userInfo.ID)
	if err != nil {
		log.Printf("[AuthService.ActivateAccount] ERROR: Failed to activate user '%s': %v", authID, err)
		return fmt.Errorf("failed to activate user: %w", err)
	}

	log.Printf("[AuthService.ActivateAccount] SUCCESS: Account activated for user '%s'", authID)
	return nil
}
