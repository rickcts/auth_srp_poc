package service

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"

	"github.com/tadglines/go-pkgs/crypto/srp"
)

var _ AuthGenerator = (*AuthService)(nil)

// NewAuthService creates a new AuthService
func NewAuthService(userRepo repository.UserRepository, stateRepo repository.StateRepository, tokenSvc TokenGenerator, cfg *config.Config) *AuthService {
	// Log SRP parameters being used, including the hash function (sha)
	return &AuthService{
		userRepo:  userRepo,
		stateRepo: stateRepo,
		tokenSvc:  tokenSvc,
		srpGroup:  cfg.SRPGroup,
		cfg:       cfg,
	}
}

// Register handles user registration
func (s *AuthService) Register(req models.RegisterRequest) error {
	if req.Username == "" || req.Salt == "" || req.Verifier == "" {
		log.Printf("[AuthService.Register] ERROR: Missing required fields for user '%s'", req.Username)
		return fmt.Errorf("username, salt, and verifier cannot be empty")
	}

	log.Printf("[AuthService.Register] Attempting to register user '%s' with Salt: %s, Verifier: %s", req.Username, req.Salt, req.Verifier)

	err := s.userRepo.CreateUserCreds(req.Username, req.Salt, req.Verifier)
	if err != nil {
		if err == repository.ErrUserExists {
			log.Printf("[AuthService.Register] WARN: User '%s' already exists", req.Username)
			return fmt.Errorf("user already exists")
		}
		log.Printf("[AuthService.Register] ERROR: Failed to store credentials for user '%s': %v", req.Username, err)
		return fmt.Errorf("failed to store user credentials: %w", err)
	}
	log.Printf("[AuthService.Register] SUCCESS: User registered: %s", req.Username)
	return nil
}

// ComputeB handles SRP step 1 (Server -> Client: salt, B)
func (s *AuthService) ComputeB(req models.AuthStep1Request) (*models.AuthStep1Response, error) {
	log.Printf("[AuthService.ComputeB] Received Step 1 request for user '%s'", req.Username)

	// Retrieve user credentials
	saltHex, verifierHex, err := s.userRepo.GetUserCredsByUsername(req.Username)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Failed to get credentials for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("failed to get user credentials: %w", err) // Could be ErrUserNotFound
	}
	log.Printf("[AuthService.ComputeB] Retrieved credentials for user '%s': Salt=%s, Verifier=%s", req.Username, saltHex, verifierHex)

	verifier, err := hex.DecodeString(verifierHex)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Invalid verifier hex format for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("invalid verifier hex format: %w", err)
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Invalid salt hex format for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("invalid salt hex format: %w", err)
	}

	srp, err := srp.NewSRP(s.srpGroup, s.cfg.HashingAlgorithm.New, nil)
	if err != nil {
		log.Printf("[AuthService.ComputeB] ERROR: Failed to create SRP instance for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("failed to create SRP instance: %w", err)
	}

	// Create SRP Server instance
	server := srp.NewServerSession([]byte(req.Username), salt, verifier)
	B := server.GetB()

	state := models.AuthSessionState{
		Username: req.Username,
		Salt:     salt,                  // This is 's'
		Server:   server,                // SRP server instance
		B:        B,                     // This is 'B'
		Expiry:   s.cfg.AuthStateExpiry, // time.Time
	}
	s.stateRepo.StoreAuthState(req.Username, state) // Assuming StoreAuthState handles expiry correctly

	// Return salt and B
	response := &models.AuthStep1Response{
		Salt:    saltHex,
		ServerB: hex.EncodeToString(B),
	}
	log.Printf("[AuthService.ComputeB] Returning Salt and ServerB for user '%s'", req.Username)
	return response, nil
}

// VerifyClientProof handles SRP step 2 (Client -> Server: A, M1) and returns Step 3 info (Server -> Client: M2)
func (s *AuthService) VerifyClientProof(req models.AuthStep2Request) (*models.AuthStep3Response, error) {
	log.Printf("[AuthService.VerifyClientProof] Received Step 2 request for user '%s': ClientA=%s, ClientProofM1=%s",
		req.Username, req.ClientA, req.ClientProofM1)

	// 1. Retrieve stored state (secret 'b'/'secret2', verifier 'V')
	session, err := s.stateRepo.GetAuthState(req.Username)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to retrieve auth state for user '%s': %v", req.Username, err)
		s.stateRepo.DeleteAuthState(req.Username)                                  // Uncomment if needed
		return nil, fmt.Errorf("failed to retrieve authentication state: %w", err) // Don't leak internal state details
	}

	// 2. Decode client public ephemeral 'A'
	bytesA, err := hex.DecodeString(req.ClientA)
	if err != nil || len(bytesA) == 0 { // Also check for empty result
		log.Printf("[AuthService.VerifyClientProof] ERROR: Invalid client public ephemeral 'A' format for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("invalid client A format: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Decoded ClientA for user '%s': %s", req.Username, hex.EncodeToString(bytesA))

	// 3. Decode client proof 'M1'
	ClientM1, err := hex.DecodeString(req.ClientProofM1)
	if err != nil || len(ClientM1) == 0 { // Also check for empty result
		log.Printf("[AuthService.VerifyClientProof] ERROR: Invalid client proof 'M1' format for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("invalid client proof M1 format: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Decoded ClientProofM1 for user '%s': %s", req.Username, hex.EncodeToString(ClientM1))

	// 4. Create SRP Server instance with retrieved state ('b'/'secret2', 'V'/verifier)
	server := session.Server
	if server == nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to re-create SRP server instance for user '%s'", req.Username)
		return nil, fmt.Errorf("failed to create SRP server instance")
	}
	log.Printf("[AuthService.VerifyClientProof] Re-created SRP server instance for user '%s'", req.Username)

	// 5. Set client public ephemeral 'A' on the server instance
	k, err := server.ComputeKey(bytesA)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to compute key for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("failed to compute key: %w", err)
	}
	log.Printf("[AuthService.VerifyClientProof] Computed key for user '%s': %s", req.Username, hex.EncodeToString(k))

	log.Printf("[AuthService.VerifyClientProof] Set ClientA on SRP server for user '%s'", req.Username)
	isValid := server.VerifyClientAuthenticator(ClientM1)
	if !isValid {
		// This means the client's M1 did not match the server's calculation! Authentication fails.
		log.Printf("[AuthService.VerifyClientProof] ERROR: Client proof M1 verification failed for user '%s': %v", req.Username, err)
		// Security Consideration: Avoid leaking *why* it failed if possible in production error messages.
		// Clean up state after failed attempt
		s.stateRepo.DeleteAuthState(req.Username)                     // Add Delete method to repo if needed
		return nil, fmt.Errorf("client proof M1 verification failed") // Generic error to client
	}
	// M1 verification successful!
	log.Printf("[AuthService.VerifyClientProof] SUCCESS: Client proof M1 verified for user '%s'", req.Username)

	err = s.stateRepo.DeleteAuthState(req.Username)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] WARN: Failed to delete auth state for user '%s' after successful auth: %v", req.Username, err)
	} else {
		log.Printf("[AuthService.VerifyClientProof] Deleted auth state for user '%s' after successful auth.", req.Username)
	}

	token, err := s.tokenSvc.GenerateToken(req.Username)
	if err != nil {
		log.Printf("[AuthService.VerifyClientProof] ERROR: Failed to generate token for user '%s': %v", req.Username, err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	M2 := server.ComputeAuthenticator(ClientM1)
	response := &models.AuthStep3Response{
		ServerProofM2: hex.EncodeToString(M2),
		SessionToken:  token,
	}
	log.Printf("[AuthService.VerifyClientProof] Returning ServerProofM2 for user '%s'", req.Username)
	return response, nil
}
