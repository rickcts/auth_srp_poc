package service

import (
	"context"
	"crypto"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/mocks"
	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tadglines/go-pkgs/crypto/srp"
)

// Helper to create a basic config for tests
func createTestConfig() *config.Config {
	// Use a known group for deterministic tests if possible, or handle variability
	// Using a smaller group for faster tests might be an option if logic allows
	return &config.Config{
		JWTSecret: "test-secret",
		SRP: config.SRPConfig{
			Group:            "rfc5054.4096",
			AuthStateExpiry:  time.Now().Add(5 * time.Minute), // Set expiry in the future
			HashingAlgorithm: crypto.SHA512,
		},
	}
}

// Helper to generate valid SRP credentials for testing
func generateTestCreds(username, password string, cfg *config.Config) (saltHex, verifierHex string, err error) {
	srpInstance, err := srp.NewSRP(cfg.SRP.Group, cfg.SRP.HashingAlgorithm.New, nil) // Match hash used in service
	if err != nil {
		return "", "", fmt.Errorf("failed to create SRP instance: %w", err)
	}
	salt, verifier, err := srpInstance.ComputeVerifier([]byte(password))
	if err != nil {
		return "", "", fmt.Errorf("failed to compute verifier: %w", err)
	}
	return hex.EncodeToString(salt), hex.EncodeToString(verifier), nil
}

func TestAuthService_Register(t *testing.T) {
	mockStateRepo := new(mocks.MockStateRepository)
	mockTokenSvc := new(mocks.MockTokenService)
	cfg := createTestConfig()

	req := models.RegisterRequest{
		Username: "testuser",
		Salt:     "somesalt",
		Verifier: "someverifier",
	}

	t.Run("Success", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("CreateUserCreds", req.Username, req.Salt, req.Verifier).Return(nil).Once()
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		err := authService.Register(context.Background(), req)

		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("UserExists", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("CreateUserCreds", req.Username, req.Salt, req.Verifier).Return(repository.ErrUserExists).Once()
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		err := authService.Register(context.Background(), req)

		require.Error(t, err)
		// Check for the specific error message the service returns, not the repo error directly
		assert.Contains(t, err.Error(), "user already exists")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("RepositoryError", func(t *testing.T) {
		repoErr := errors.New("database error")
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("CreateUserCreds", req.Username, req.Salt, req.Verifier).Return(repoErr).Once()
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		err := authService.Register(context.Background(), req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store user credentials")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("EmptyFields", func(t *testing.T) {
		emptyReq := models.RegisterRequest{Username: "", Salt: "", Verifier: ""}
		mockUserRepo := new(mocks.MockUserRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		err := authService.Register(context.Background(), emptyReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username, salt, and verifier cannot be empty")
		// No mock calls expected
		mockUserRepo.AssertNotCalled(t, "CreateUserCreds", mock.Anything, mock.Anything, mock.Anything)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestAuthService_ComputeB(t *testing.T) {
	mockTokenSvc := new(mocks.MockTokenService) // Not used
	cfg := createTestConfig()

	username := "testuser"
	password := "password123"
	saltHex, verifierHex, err := generateTestCreds(username, password, cfg)
	require.NoError(t, err, "Failed to generate test creds")

	req := models.AuthStep1Request{Username: username}

	t.Run("Success", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return(saltHex, verifierHex, nil).Once()
		// Expect StoreAuthState to be called, capture the state to verify expiry later if needed
		mockStateRepo := new(mocks.MockStateRepository)
		mockStateRepo.On("StoreAuthState", username, mock.AnythingOfType("models.AuthSessionState")).Return(nil).Once()
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, saltHex, resp.Salt)
		assert.NotEmpty(t, resp.ServerB, "ServerB should not be empty")

		// Verify B is valid hex
		_, decodeErr := hex.DecodeString(resp.ServerB)
		assert.NoError(t, decodeErr, "ServerB should be valid hex")

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return("", "", repository.ErrUserNotFound).Once()
		mockStateRepo := new(mocks.MockStateRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)                // Check underlying error
		assert.Contains(t, err.Error(), "failed to get user credentials") // Check service layer error message

		mockUserRepo.AssertExpectations(t)
		mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("InvalidVerifierHex", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return(saltHex, "invalid-hex", nil).Once()
		mockStateRepo := new(mocks.MockStateRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid verifier hex format")

		mockUserRepo.AssertExpectations(t)
		mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("InvalidSaltHex", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return("invalid-hex", verifierHex, nil).Once()
		mockStateRepo := new(mocks.MockStateRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid salt hex format")

		mockUserRepo.AssertExpectations(t)
		mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("RepositoryError", func(t *testing.T) {
		repoErr := errors.New("database error")
		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return("", "", repoErr).Once()
		mockStateRepo := new(mocks.MockStateRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, cfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to get user credentials")

		mockUserRepo.AssertExpectations(t)
		mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("SRPInstanceError", func(t *testing.T) {
		// Create a config with an invalid SRP group
		badCfg := createTestConfig()
		badCfg.SRP.Group = "invalid-group"

		mockUserRepo := new(mocks.MockUserRepository)
		mockUserRepo.On("GetUserCredsByUsername", username).Return(saltHex, verifierHex, nil).Once()
		mockStateRepo := new(mocks.MockStateRepository)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, badCfg)
		resp, err := authService.ComputeB(context.Background(), req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to create SRP instance")
		mockUserRepo.AssertExpectations(t)
	})
}

// --- Helper for VerifyClientProof Setup ---
type verifyClientProofTestData struct {
	cfg           *config.Config
	username      string
	password      string
	validState    models.AuthSessionState
	req           models.AuthStep2Request
	serverSession *srp.ServerSession // Needed for M2 verification
	clientM1Bytes []byte             // Needed for M2 verification
}

func setupVerifyClientProofData(t *testing.T) verifyClientProofTestData {
	t.Helper() // Marks this as a test helper

	cfg := createTestConfig()
	username := "testuser"
	password := "password123"

	// 1. Generate real Salt, Verifier
	saltHex, verifierHex, err := generateTestCreds(username, password, cfg)
	require.NoError(t, err, "Setup: Failed to generate test creds")
	saltBytes, err := hex.DecodeString(saltHex)
	require.NoError(t, err, "Setup: Failed to decode salt hex")
	verifierBytes, err := hex.DecodeString(verifierHex)
	require.NoError(t, err, "Setup: Failed to decode verifier hex")

	// 2. Simulate Step 1: Create Server Session and get B
	srpInstance, err := srp.NewSRP(cfg.SRP.Group, sha512.New, nil)
	require.NoError(t, err, "Setup: Failed to create SRP instance")
	serverSession := srpInstance.NewServerSession([]byte(username), saltBytes, verifierBytes)
	serverBBytes := serverSession.GetB()

	// 3. Simulate Client Side: Create Client Session, Compute A, M1
	clientSession := srpInstance.NewClientSession([]byte(username), []byte(password))
	clientABytes := clientSession.GetA()
	clientAHex := hex.EncodeToString(clientABytes)
	// Client computes key using Server's B and its own salt/identity/password
	// Note: The signature might vary slightly between SRP libraries. Adjust if needed.
	// Assuming ComputeKey needs salt and B.
	_, err = clientSession.ComputeKey(saltBytes, serverBBytes)
	require.NoError(t, err, "Setup: Client failed to compute key")
	clientM1Bytes := clientSession.ComputeAuthenticator()
	clientM1Hex := hex.EncodeToString(clientM1Bytes)

	// 4. Prepare the state that *should* be in the repo
	validState := models.AuthSessionState{
		Username: username,
		Salt:     saltBytes,
		Server:   serverSession, // The *actual* server session from step 1 simulation
		B:        serverBBytes,
		Expiry:   cfg.SRP.AuthStateExpiry, // Use expiry from config
	}

	// 5. Prepare the request for Step 2
	req := models.AuthStep2Request{
		Username:      username,
		ClientA:       clientAHex,
		ClientProofM1: clientM1Hex,
	}

	return verifyClientProofTestData{
		cfg:           cfg,
		username:      username,
		password:      password,
		validState:    validState,
		req:           req,
		serverSession: serverSession,
		clientM1Bytes: clientM1Bytes,
	}
}

// --- Refactored TestAuthService_VerifyClientProof ---
func TestAuthService_VerifyClientProof(t *testing.T) {

	t.Run("Success", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository) // Still needed for NewAuthService
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Mock expectations
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Once()
		expectedToken := "test-jwt-token"
		mockTokenSvc.On("GenerateToken", data.username).Return(expectedToken, nil).Once()

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), data.req)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, expectedToken, resp.SessionToken)
		assert.NotEmpty(t, resp.ServerProofM2, "ServerProofM2 should not be empty")

		// Verify M2 (optional but good) - Server computes M2 based on *client's* M1
		serverM2Bytes := data.serverSession.ComputeAuthenticator(data.clientM1Bytes)
		assert.Equal(t, hex.EncodeToString(serverM2Bytes), resp.ServerProofM2)

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertExpectations(t)
	})

	t.Run("StateNotFound", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t) // Need req from data
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Mock expectations
		mockStateRepo.On("GetAuthState", data.username).Return(nil, repository.ErrStateNotFound).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Maybe() // Maybe called depending on exact error handling path

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
		assert.Contains(t, err.Error(), "failed to retrieve authentication state")

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
	})

	t.Run("InvalidClientProofM1", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Modify request for this test case
		badReq := data.req
		badReq.ClientProofM1 = hex.EncodeToString([]byte("invalidproof1234567890")) // Use a different invalid proof

		// Mock expectations
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Once() // Should be called on failure path too

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "client proof M1 verification failed")

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
	})

	t.Run("InvalidClientAHex", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Modify request
		badReq := data.req
		badReq.ClientA = "invalid-hex-a-value"

		// Mock expectations (GetAuthState is called before A is decoded)
		// We don't know if GetAuthState will succeed or fail first in a real scenario,
		// but the service logic checks GetAuthState first.
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		// Delete might or might not be called depending on where the A decoding fails in service
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Maybe()

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid client A format")

		// Assert that GetAuthState was at least called
		mockStateRepo.AssertCalled(t, "GetAuthState", data.username)
		// Assert that token generation was definitely not called
		mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
		// Assert all expectations set on mockStateRepo (including the Maybe Delete)
		mockStateRepo.AssertExpectations(t)
	})

	t.Run("TokenGenerationError", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Mock expectations
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Once() // Called before token generation
		tokenErr := errors.New("jwt signing error")
		mockTokenSvc.On("GenerateToken", data.username).Return("", tokenErr).Once()

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, tokenErr)
		assert.Contains(t, err.Error(), "failed to generate token")

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertExpectations(t)
	})

	t.Run("InvalidClientM1Hex", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Modify request
		badReq := data.req
		badReq.ClientProofM1 = "invalid-hex-m1-value"

		// Mock expectations (GetAuthState is called before M1 is decoded)
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Maybe()

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid client proof M1 format")

		mockStateRepo.AssertCalled(t, "GetAuthState", data.username)
		mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
		mockStateRepo.AssertExpectations(t)
	})

	t.Run("ComputeKeyError", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		badState := data.validState
		badState.Server = nil
		mockStateRepo.On("GetAuthState", data.username).Return(&badState, nil).Once()
		mockStateRepo.On("DeleteAuthState", data.username).Return(nil).Maybe()

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to create SRP server instance")

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)

	})

	t.Run("DeleteAuthStateError", func(t *testing.T) {
		// Setup inside subtest
		data := setupVerifyClientProofData(t)
		mockUserRepo := new(mocks.MockUserRepository)
		mockStateRepo := new(mocks.MockStateRepository)
		mockTokenSvc := new(mocks.MockTokenService)
		authService := NewAuthService(mockUserRepo, mockStateRepo, mockTokenSvc, data.cfg)

		// Mock expectations
		mockStateRepo.On("GetAuthState", data.username).Return(&data.validState, nil).Once()
		deleteErr := errors.New("db connection lost")
		mockStateRepo.On("DeleteAuthState", data.username).Return(deleteErr).Once() // Simulate error during delete
		expectedToken := "test-jwt-token"
		mockTokenSvc.On("GenerateToken", data.username).Return(expectedToken, nil).Once() // Token generation still happens

		// Execute
		resp, err := authService.VerifyClientProof(context.Background(), data.req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, expectedToken, resp.SessionToken)

		serverM2Bytes := data.serverSession.ComputeAuthenticator(data.clientM1Bytes)
		assert.Equal(t, hex.EncodeToString(serverM2Bytes), resp.ServerProofM2)

		mockStateRepo.AssertExpectations(t)
		mockTokenSvc.AssertExpectations(t)
	})
}
