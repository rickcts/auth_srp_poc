package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/mocks"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tadglines/go-pkgs/crypto/srp"
)

// Common test constants
const (
	testAuthID      = "test@example.com"
	testDisplayName = "Test User"
	testPassword    = "password123"
	testUserID      = int64(1)
)

// Helper to generate valID SRP credentials for testing
func generateTestCreds(authID, password string, cfg *config.Config) (saltHex, verifierHex string, err error) {
	srpInstance, err := srp.NewSRP(cfg.SRP.Group, cfg.SRP.HashingAlgorithm.New, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create SRP instance: %w", err)
	}
	salt, verifier, err := srpInstance.ComputeVerifier([]byte(password))
	if err != nil {
		return "", "", fmt.Errorf("failed to compute verifier: %w", err)
	}
	return hex.EncodeToString(salt), hex.EncodeToString(verifier), nil
}

// srpAuthServiceTestDeps holds common dependencies for SRPAuthService tests
type srpAuthServiceTestDeps struct {
	mockUserRepo               *mocks.MockUserRepository
	mockStateRepo              *mocks.MockStateRepository
	mockSessionRepo            *mocks.MockSessionRepository
	mockTokenSvc               *mocks.MockJWTGenerator
	mockPasswordResetTokenRepo *mocks.MockPasswordResetTokenRepository
	mockEmailSvc               *mocks.MockEmailService
	cfg                        *config.Config
	authService                SRPAuthGenerator // Use the interface
}

// setupSRPAuthServiceTest initializes mocks and the service for testing.
func setupSRPAuthServiceTest(t *testing.T) srpAuthServiceTestDeps {
	t.Helper()
	cfg := mocks.CreateTestConfigForSessionTests()

	deps := srpAuthServiceTestDeps{
		mockUserRepo:               new(mocks.MockUserRepository),
		mockStateRepo:              new(mocks.MockStateRepository),
		mockSessionRepo:            new(mocks.MockSessionRepository),
		mockTokenSvc:               new(mocks.MockJWTGenerator),
		mockPasswordResetTokenRepo: new(mocks.MockPasswordResetTokenRepository),
		mockEmailSvc:               new(mocks.MockEmailService),
		cfg:                        cfg,
	}
	deps.authService = NewSRPAuthService(
		deps.mockUserRepo,
		deps.mockStateRepo,
		deps.mockSessionRepo,
		deps.mockTokenSvc,
		deps.mockPasswordResetTokenRepo,
		deps.mockEmailSvc,
		deps.cfg,
	)
	return deps
}

func TestAuthService_Register(t *testing.T) {
	ctx := context.Background()

	defaultReq := models.SRPRegisterRequest{
		AuthID:      testAuthID,
		DisplayName: testDisplayName,
		Salt:        "somesalt",
		Verifier:    "someverifier",
	}
	defaultExpectedExtras := map[string]string{"salt": defaultReq.Salt, "verifier": defaultReq.Verifier}

	// Define error instances to be reused for consistent checking with errors.Is
	errDbCheck := errors.New("db check error")
	errDbCreate := errors.New("db create error")
	testCases := []struct {
		name                      string
		req                       models.SRPRegisterRequest
		setupMocks                func(deps srpAuthServiceTestDeps, req models.SRPRegisterRequest)
		expectedErrSubstring      string
		expectedSpecificError     error
		assertCreateUserNotCalled bool
	}{
		{
			name: "Success",
			req:  defaultReq,
			setupMocks: func(deps srpAuthServiceTestDeps, req models.SRPRegisterRequest) {
				deps.mockUserRepo.On("CheckIfUserExists", ctx, req.AuthID).Return(false, nil).Once()
				deps.mockUserRepo.On("CreateUser", ctx, req.AuthID, req.DisplayName, "SRP6", defaultExpectedExtras).Return(nil).Once()
			},
		},
		{
			name: "UserExists",
			req:  defaultReq,
			setupMocks: func(deps srpAuthServiceTestDeps, req models.SRPRegisterRequest) {
				deps.mockUserRepo.On("CheckIfUserExists", ctx, req.AuthID).Return(true, nil).Once()
			},
			expectedErrSubstring:      "user already exists",
			assertCreateUserNotCalled: true,
		},
		{
			name: "RepositoryErrorOnCheckIfUserExists",
			req:  defaultReq,
			setupMocks: func(deps srpAuthServiceTestDeps, req models.SRPRegisterRequest) {
				deps.mockUserRepo.On("CheckIfUserExists", ctx, req.AuthID).Return(false, errDbCheck).Once()
			},
			expectedErrSubstring:      "failed to check if user exists",
			expectedSpecificError:     errDbCheck,
			assertCreateUserNotCalled: true,
		},
		{
			name: "RepositoryErrorOnCreateUser",
			req:  defaultReq,
			setupMocks: func(deps srpAuthServiceTestDeps, req models.SRPRegisterRequest) {
				deps.mockUserRepo.On("CheckIfUserExists", ctx, req.AuthID).Return(false, nil).Once()
				deps.mockUserRepo.On("CreateUser", ctx, req.AuthID, req.DisplayName, "SRP6", defaultExpectedExtras).Return(errDbCreate).Once()
			},
			expectedErrSubstring:  "failed to register user",
			expectedSpecificError: errDbCreate,
		},
		{
			name:                      "EmptyAuthID",
			req:                       models.SRPRegisterRequest{AuthID: "", Salt: "salt", Verifier: "verifier"},
			expectedErrSubstring:      "username, salt, and verifier cannot be empty",
			assertCreateUserNotCalled: true,
		},
		{
			name:                      "EmptySalt",
			req:                       models.SRPRegisterRequest{AuthID: testAuthID, Salt: "", Verifier: "verifier"},
			expectedErrSubstring:      "username, salt, and verifier cannot be empty",
			assertCreateUserNotCalled: true,
		},
		{
			name:                      "EmptyVerifier",
			req:                       models.SRPRegisterRequest{AuthID: testAuthID, Salt: "salt", Verifier: ""},
			expectedErrSubstring:      "username, salt, and verifier cannot be empty",
			assertCreateUserNotCalled: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps := setupSRPAuthServiceTest(t)

			if tc.setupMocks != nil {
				tc.setupMocks(deps, tc.req)
			}

			err := deps.authService.Register(ctx, tc.req)

			if tc.expectedErrSubstring != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrSubstring)
				if tc.expectedSpecificError != nil {
					assert.ErrorIs(t, err, tc.expectedSpecificError)
				}
			} else {
				require.NoError(t, err)
			}

			deps.mockUserRepo.AssertExpectations(t)
			if tc.assertCreateUserNotCalled {
				deps.mockUserRepo.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestAuthService_ComputeB(t *testing.T) {
	ctx := context.Background()
	deps := setupSRPAuthServiceTest(t) // Setup once for all subtests in ComputeB

	saltHex, verifierHex, err := generateTestCreds(testAuthID, testPassword, deps.cfg)
	require.NoError(t, err, "Failed to generate test creds")

	req := models.AuthStep1Request{AuthID: testAuthID}

	t.Run("Success", func(t *testing.T) {
		// Reset UserRepo and StateRepo mocks for this specific subtest if needed, or use deps directly
		// For this test, we'll re-initialize them to ensure clean state for this sub-test
		subTestDeps := setupSRPAuthServiceTest(t)

		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return(&models.UserInfo{
			AuthID:       testAuthID,
			AuthProvider: "SRP6",
			AuthExtras:   map[string]string{"salt": saltHex, "verifier": verifierHex},
		}, nil).Once()
		subTestDeps.mockStateRepo.On("StoreAuthState", testAuthID, mock.AnythingOfType("models.AuthSessionState")).Return(nil).Once()

		resp, err := subTestDeps.authService.ComputeB(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, saltHex, resp.Salt)
		assert.NotEmpty(t, resp.ServerB, "ServerB should not be empty")

		// Verify B is valID hex
		_, decodeErr := hex.DecodeString(resp.ServerB)
		assert.NoError(t, decodeErr, "ServerB should be valid hex")

		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertExpectations(t)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		subTestDeps := setupSRPAuthServiceTest(t)
		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return((*models.UserInfo)(nil), repository.ErrUserNotFound).Once()
		resp, err := subTestDeps.authService.ComputeB(ctx, req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)                // Check underlying error
		assert.Contains(t, err.Error(), "failed to get user credentials") // Check service layer error message

		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("InvalidVerifierHex", func(t *testing.T) {
		subTestDeps := setupSRPAuthServiceTest(t)
		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return(&models.UserInfo{
			AuthExtras: map[string]string{"salt": saltHex, "verifier": "invalid-hex"},
		}, nil).Once()
		resp, err := subTestDeps.authService.ComputeB(ctx, req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid verifier hex format")

		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("InvalidSaltHex", func(t *testing.T) {
		subTestDeps := setupSRPAuthServiceTest(t)
		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return(&models.UserInfo{
			AuthExtras: map[string]string{"salt": "invalid-hex", "verifier": verifierHex},
		}, nil).Once()
		resp, err := subTestDeps.authService.ComputeB(ctx, req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid salt hex format")

		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("RepositoryError", func(t *testing.T) {
		subTestDeps := setupSRPAuthServiceTest(t)
		repoErr := errors.New("database error")
		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return((*models.UserInfo)(nil), repoErr).Once()
		resp, err := subTestDeps.authService.ComputeB(ctx, req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to get user credentials")

		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})

	t.Run("SRPInstanceError", func(t *testing.T) {
		subTestDeps := setupSRPAuthServiceTest(t)
		badCfg := *(subTestDeps.cfg) // Create a copy to modify
		badCfg.SRP.Group = "invalid-group"
		// Re-initialize service with bad config
		authServiceWithBadCfg := NewSRPAuthService(
			subTestDeps.mockUserRepo,
			subTestDeps.mockStateRepo,
			subTestDeps.mockSessionRepo,
			subTestDeps.mockTokenSvc,
			subTestDeps.mockPasswordResetTokenRepo,
			subTestDeps.mockEmailSvc,
			&badCfg,
		)

		// GetUserInfoByAuthID is called before SRP instance creation
		subTestDeps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthID).Return(&models.UserInfo{
			AuthExtras: map[string]string{"salt": saltHex, "verifier": verifierHex},
		}, nil).Once()
		resp, err := authServiceWithBadCfg.ComputeB(ctx, req)

		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to create SRP instance")
		subTestDeps.mockUserRepo.AssertExpectations(t)
		subTestDeps.mockStateRepo.AssertNotCalled(t, "StoreAuthState", mock.Anything, mock.Anything)
	})
}

// --- Helper for VerifyClientProof Setup ---
type verifyClientProofTestData struct {
	cfg           *config.Config
	userID        int64
	authID        string
	password      string
	validState    models.AuthSessionState
	req           models.AuthStep2Request
	serverSession *srp.ServerSession // Needed for M2 verification
	clientM1Bytes []byte             // Needed for M2 verification
}

func setupVerifyClientProofData(t *testing.T) verifyClientProofTestData {
	t.Helper() // Marks this as a test helper

	cfg := mocks.CreateTestConfigForSessionTests()

	// 1. Generate real Salt, Verifier
	saltHex, verifierHex, err := generateTestCreds(testAuthID, testPassword, cfg)
	require.NoError(t, err, "Setup: Failed to generate test creds")
	saltBytes, err := hex.DecodeString(saltHex)
	require.NoError(t, err, "Setup: Failed to decode salt hex")
	verifierBytes, err := hex.DecodeString(verifierHex)
	require.NoError(t, err, "Setup: Failed to decode verifier hex")

	// 2. Simulate Step 1: Create Server Session and get B
	srpInstance, err := srp.NewSRP(cfg.SRP.Group, cfg.SRP.HashingAlgorithm.New, nil)
	require.NoError(t, err, "Setup: Failed to create SRP instance")
	serverSession := srpInstance.NewServerSession([]byte(testAuthID), saltBytes, verifierBytes)
	serverBBytes := serverSession.GetB()

	// 3. Simulate Client SIDe: Create Client Session, Compute A, M1
	clientSession := srpInstance.NewClientSession([]byte(testAuthID), []byte(testPassword))
	clientABytes := clientSession.GetA()
	clientAHex := hex.EncodeToString(clientABytes)
	// Client computes key using Server's B and its own salt/IDentity/password
	// Note: The signature might vary slightly between SRP libraries. Adjust if needed.
	// Assuming ComputeKey needs salt and B.
	_, err = clientSession.ComputeKey(saltBytes, serverBBytes)
	require.NoError(t, err, "Setup: Client failed to compute key")
	clientM1Bytes := clientSession.ComputeAuthenticator()
	clientM1Hex := hex.EncodeToString(clientM1Bytes)

	// 4. Prepare the state that *should* be in the repo
	validState := models.AuthSessionState{
		AuthID: testAuthID,
		Salt:   saltBytes,
		Server: serverSession, // The *actual* server session from step 1 simulation
		B:      serverBBytes,
		Expiry: cfg.SRP.AuthStateExpiry,
	}

	// 5. Prepare the request for Step 2
	req := models.AuthStep2Request{
		AuthID:        testAuthID,
		ClientA:       clientAHex,
		ClientProofM1: clientM1Hex,
	}

	return verifyClientProofTestData{
		cfg:           cfg,
		userID:        testUserID,   // Use constant
		authID:        testAuthID,   // Use constant
		password:      testPassword, // Use constant
		validState:    validState,
		req:           req,
		serverSession: serverSession,
		clientM1Bytes: clientM1Bytes,
	}
}

func TestAuthService_VerifyClientProof(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Mock expectations
		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, data.authID).Return(&models.UserInfo{
			ID:           data.userID,
			AuthID:       data.authID,
			AuthProvider: "SRP6",
			AuthExtras:   map[string]string{"salt": "dummySalt", "verifier": "dummyVerifier"}, // Not strictly used by SRP logic here
		}, nil).Once()
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()
		deps.mockStateRepo.On("DeleteAuthState", data.authID).Return(nil).Once()
		expectedToken := "test-jwt-token"
		expectedExpiry := time.Now().Add(1 * time.Hour)
		deps.mockTokenSvc.On("GenerateToken", data.authID).Return(expectedToken, expectedExpiry, nil).Once()
		deps.mockSessionRepo.On("StoreSession", ctx, mock.AnythingOfType("*models.Session")).Return(nil).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, data.req)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, expectedToken, resp.SessionToken)
		assert.NotEmpty(t, resp.ServerProofM2, "ServerProofM2 should not be empty")

		// Verify M2 (optional but good) - Server computes M2 based on *client's* M1
		serverM2Bytes := data.serverSession.ComputeAuthenticator(data.clientM1Bytes)
		assert.Equal(t, hex.EncodeToString(serverM2Bytes), resp.ServerProofM2)

		deps.mockUserRepo.AssertExpectations(t)
		deps.mockStateRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertExpectations(t)
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("StateNotFound", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Mock expectations
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(nil, repository.ErrStateNotFound).Once()
		deps.mockStateRepo.On("DeleteAuthState", data.authID).Return(nil).Once() // Service calls this on GetAuthState failure

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
		assert.Contains(t, err.Error(), "failed to retrieve authentication state")

		deps.mockStateRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
	})

	t.Run("InvalidClientProofM1", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Modify request for this test case
		badReq := data.req
		badReq.ClientProofM1 = hex.EncodeToString([]byte("invalidproof1234567890")) // Use a different invalid proof

		// Mock expectations
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()
		deps.mockStateRepo.On("DeleteAuthState", data.authID).Return(nil).Once() // Called on M1 verification failure

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "client proof M1 verification failed")

		deps.mockStateRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
	})

	t.Run("InvalidClientAHex", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Modify request
		badReq := data.req
		badReq.ClientA = "invalid-hex-a-value"

		// Mock expectations (GetAuthState is called before A is decoded)
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid client A format")

		deps.mockStateRepo.AssertCalled(t, "GetAuthState", data.authID)
		deps.mockStateRepo.AssertNotCalled(t, "DeleteAuthState", data.authID) // Not called if A decode fails
		deps.mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
		deps.mockStateRepo.AssertExpectations(t)
	})

	t.Run("TokenGenerationError", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, data.authID).Return(
			&models.UserInfo{
				ID:           data.userID,
				AuthID:       data.authID,
				AuthProvider: "SRP6",
				AuthExtras:   map[string]string{"salt": "dummySalt", "verifier": "dummyVerifier"},
			}, nil).Once()

		// Mock expectations
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()
		deps.mockStateRepo.On("DeleteAuthState", data.authID).Return(nil).Once() // Called before token generation
		tokenErr := errors.New("jwt signing error")
		deps.mockTokenSvc.On("GenerateToken", data.authID).Return("", time.Time{}, tokenErr).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.ErrorIs(t, err, tokenErr)
		assert.Contains(t, err.Error(), "failed to generate token")

		deps.mockUserRepo.AssertExpectations(t)
		deps.mockStateRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertExpectations(t)
	})

	t.Run("InvalidClientM1Hex", func(t *testing.T) {
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Modify request
		badReq := data.req
		badReq.ClientProofM1 = "invalid-hex-m1-value"

		// Mock expectations (GetAuthState is called before M1 is decoded)
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, badReq)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid client proof M1 format")

		deps.mockStateRepo.AssertCalled(t, "GetAuthState", data.authID)
		deps.mockStateRepo.AssertNotCalled(t, "DeleteAuthState", data.authID) // Not called if M1 decode fails
		deps.mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
		deps.mockStateRepo.AssertExpectations(t)
	})

	t.Run("ComputeKeyError", func(t *testing.T) {
		// This test simulates session.Server being nil, which means SRP server instance couldn't be re-created.
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		badState := data.validState
		badState.Server = nil // Simulate a corrupted or missing server session part
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&badState, nil).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(context.Background(), data.req)

		// Assert
		require.Error(t, err)
		require.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to create SRP server instance")

		deps.mockStateRepo.AssertCalled(t, "GetAuthState", data.authID)
		deps.mockStateRepo.AssertNotCalled(t, "DeleteAuthState", data.authID) // Not called if server is nil
		deps.mockTokenSvc.AssertNotCalled(t, "GenerateToken", mock.Anything)
		deps.mockUserRepo.AssertNotCalled(t, "GetUserInfoByAuthID", mock.Anything, mock.Anything)
		deps.mockStateRepo.AssertExpectations(t)
	})

	t.Run("DeleteAuthStateError", func(t *testing.T) {
		// This tests the scenario where DeleteAuthState itself returns an error,
		// but the overall flow should succeed as it's a cleanup step.
		deps := setupSRPAuthServiceTest(t)
		data := setupVerifyClientProofData(t)

		// Mock expectations
		deps.mockStateRepo.On("GetAuthState", data.authID).Return(&data.validState, nil).Once()
		deleteErr := errors.New("db connection lost")
		deps.mockStateRepo.On("DeleteAuthState", data.authID).Return(deleteErr).Once() // Simulate error during delete

		expectedToken := "test-jwt-token"
		expectedExpiry := time.Now().Add(1 * time.Hour)
		deps.mockTokenSvc.On("GenerateToken", data.authID).Return(expectedToken, expectedExpiry, nil).Once() // Token generation still happens

		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, data.authID).Return(
			&models.UserInfo{
				ID:           data.userID,
				AuthID:       data.authID,
				AuthProvider: "SRP6",
				AuthExtras:   map[string]string{"salt": "dummySalt", "verifier": "dummyVerifier"},
			}, nil).Once()
		deps.mockSessionRepo.On("StoreSession", ctx, mock.AnythingOfType("*models.Session")).Return(nil).Once()

		// Execute
		resp, err := deps.authService.VerifyClientProof(ctx, data.req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, expectedToken, resp.SessionToken)

		serverM2Bytes := data.serverSession.ComputeAuthenticator(data.clientM1Bytes)
		assert.Equal(t, hex.EncodeToString(serverM2Bytes), resp.ServerProofM2)

		deps.mockUserRepo.AssertExpectations(t)
		deps.mockStateRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertExpectations(t)
		deps.mockSessionRepo.AssertExpectations(t)
	})
}
