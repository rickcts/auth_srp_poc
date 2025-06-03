package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"

	"github.com/tadglines/go-pkgs/crypto/srp"
)

var _ SRPAuthGenerator = (*SRPAuthService)(nil)

// NewSRPAuthService creates a new SRPAuthService
func NewSRPAuthService(
	userRepo repository.UserRepository,
	stateRepo repository.StateRepository,
	sessionRepo repository.SessionRepository,
	tokenSvc JWTGenerator,
	passwordResetTokenRepo repository.PasswordResetTokenRepository, // Added
	emailSvc EmailService, // Added
	cfg *config.Config,
) *SRPAuthService {
	return &SRPAuthService{
		userRepo:               userRepo,
		stateRepo:              stateRepo,
		sessionRepo:            sessionRepo,
		tokenSvc:               tokenSvc,
		passwordResetTokenRepo: passwordResetTokenRepo, // Initialize
		emailSvc:               emailSvc,               // Initialize
		srpGroup:               cfg.SRP.Group,
		cfg:                    cfg,
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
		return fmt.Errorf("user already exists")
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
		s.stateRepo.DeleteAuthState(req.AuthID)                                    // Uncomment if needed
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

	user_info, err := s.userRepo.GetUserInfoByAuthID(ctx, req.AuthID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to get user info for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	userID := user_info.ID

	// Generate session token
	sessionTokenString, sessionTokenExpiry, err := s.tokenSvc.GenerateToken(userID)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to generate session token for user '%s': %v", req.AuthID, err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Create and store the user session
	sessionRecord := &models.Session{
		SessionID: sessionTokenString,
		UserID:    userID,
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

// ChangePassword handles changing the password for an authenticated user.
func (s *SRPAuthService) ChangePassword(ctx context.Context, authID string, req models.ChangePasswordRequest) error {
	if authID == "" {
		return fmt.Errorf("authID cannot be empty")
	}
	if req.NewSalt == "" || req.NewVerifier == "" {
		log.Printf("[AuthService.ChangePassword] ERROR: Missing new salt or verifier for user '%s'", authID)
		return fmt.Errorf("new salt and verifier cannot be empty")
	}

	log.Printf("[AuthService.ChangePassword] Attempting to change password for user '%s'", authID)

	// Update the user's salt and verifier in the repository
	err := s.userRepo.UpdateUserSRPAuth(ctx, authID, req.NewSalt, req.NewVerifier)
	if err != nil {
		log.Printf("[AuthService.ChangePassword] ERROR: Failed to update SRP auth for user '%s': %v", authID, err)
		return fmt.Errorf("failed to change password: %w", err)
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Printf("[AuthService.ChangePassword] ERROR: Failed to get user info for user '%s': %v", authID, err)
		return fmt.Errorf("failed to get user info: %w", err)
	}

	s.sessionRepo.DeleteUserSessions(ctx, userInfo.ID, "")
	log.Printf("[AuthService.ChangePassword] SUCCESS: Password changed for user '%s'. Other sessions will be signed out.", authID)
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

	err = s.passwordResetTokenRepo.StoreResetToken(ctx, req.AuthID, resetCode, expiry)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to store password reset code for '%s': %v", req.AuthID, err)
		return fmt.Errorf("failed to initiate password reset") // Internal error
	}

	appName := "Your Application"
	err = s.emailSvc.SendPasswordResetEmail(ctx, req.AuthID, resetCode, appName)
	if err != nil {
		log.Printf("[AuthService.InitiatePasswordReset] ERROR: Failed to send password reset email to '%s': %v", req.AuthID, err)
		// If email sending fails, the token is still stored. This might be acceptable,
		// or you might want to roll back token storage (though less critical for a short-lived token).
		return fmt.Errorf("failed to send password reset email") // Internal error
	}

	log.Printf("[AuthService.InitiatePasswordReset] SUCCESS: Password reset code sent for '%s'", req.AuthID)
	return nil
}

// CompletePasswordReset completes the password reset flow.
func (s *SRPAuthService) CompletePasswordReset(ctx context.Context, req models.CompletePasswordResetRequest) error {
	if req.Token == "" || req.NewSalt == "" || req.NewVerifier == "" {
		return fmt.Errorf("token, new salt, and new verifier cannot be empty")
	}

	log.Printf("[AuthService.CompletePasswordReset] Attempting to complete password reset with code: %s", req.Token)

	// req.Token is now the 6-digit code
	authID, err := s.passwordResetTokenRepo.ValidateAndConsumeResetToken(ctx, req.Token)
	if err != nil {
		log.Printf("[AuthService.CompletePasswordReset] ERROR: Invalid or expired reset code '%s': %v", req.Token, err)
		return fmt.Errorf("invalid or expired password reset code: %w", err) // Propagate specific error like ErrPasswordResetTokenNotFound
	}

	log.Printf("[AuthService.CompletePasswordReset] Code validated for authID '%s'. Updating password.", authID)

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
