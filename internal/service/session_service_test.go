package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/mocks"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testSessionToken      = "test-session-token-123"
	testNewSessionToken   = "new-session-token-456"
	testUserIDSession     = int64(1)
	testAnotherUserID     = int64(2)
	testAuthIDSession     = "test-user-1"
	testAuthIDAnotherUser = "test-user-2"
	genericErrMsg         = "a generic error occurred"
	sessionNotFoundErrMsg = "session not found or expired"
)

// sessionServiceTestDeps holds common dependencies for SessionService tests
type sessionServiceTestDeps struct {
	mockUserRepo    *mocks.MockUserRepository
	mockSessionRepo *mocks.MockSessionRepository
	mockTokenSvc    *mocks.MockJWTGenerator
	cfg             *config.Config
	service         SessionGenerator
}

// setupSessionServiceTest initializes mocks and the service for testing session methods.
func setupSessionServiceTest(t *testing.T) sessionServiceTestDeps {
	t.Helper()
	cfg := mocks.CreateTestConfigForSessionTests() // Keep cfg if mocks might use it, though SessionService itself doesn't.

	deps := sessionServiceTestDeps{
		mockUserRepo:    new(mocks.MockUserRepository),
		mockSessionRepo: new(mocks.MockSessionRepository),
		mockTokenSvc:    new(mocks.MockJWTGenerator),
		cfg:             cfg,
	}
	deps.service = NewSessionService(
		deps.mockSessionRepo,
		deps.mockUserRepo,
		deps.mockTokenSvc,
	)
	return deps
}

func TestSRPAuthService_SignOut(t *testing.T) {
	ctx := context.Background()

	t.Run("Success_SignOut", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once()

		err := deps.service.SignOut(ctx, testSessionToken)
		require.NoError(t, err)
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("SuccessWhenSessionNotFound_SignOut", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(repository.ErrSessionNotFound).Once()

		err := deps.service.SignOut(ctx, testSessionToken)
		require.NoError(t, err) // ErrSessionNotFound is treated as success for SignOut
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("ErrorEmptyToken_SignOut", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		err := deps.service.SignOut(ctx, "")
		require.Error(t, err)
		assert.EqualError(t, err, "session token cannot be empty")
		deps.mockSessionRepo.AssertNotCalled(t, "DeleteSession", mock.Anything, mock.Anything)
	})

	t.Run("ErrorRepoFailure_SignOut", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		repoErr := errors.New(genericErrMsg)
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(repoErr).Once()

		err := deps.service.SignOut(ctx, testSessionToken)
		require.Error(t, err)
		assert.True(t, errors.Is(err, repoErr))
		assert.Contains(t, err.Error(), "failed to sign out")
		deps.mockSessionRepo.AssertExpectations(t)
	})
}

func TestSessionService_ExtendUserSession(t *testing.T) {
	ctx := context.Background()
	validExpiry := time.Now().UTC().Add(1 * time.Hour)
	newExpiry := time.Now().UTC().Add(2 * time.Hour)

	currentValidSession := &models.Session{
		SessionID: testSessionToken,
		UserID:    testUserIDSession,
		AuthID:    testAuthIDSession,
		Expiry:    validExpiry,
	}

	t.Run("Success_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(currentValidSession, nil).Once()
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once()
		deps.mockTokenSvc.On("GenerateToken", testAuthIDSession).Return(testNewSessionToken, newExpiry, nil).Once()
		deps.mockSessionRepo.On("StoreSession", ctx, mock.AnythingOfType("*models.Session")).
			Run(func(args mock.Arguments) {
				storedSession := args.Get(1).(*models.Session)
				assert.Equal(t, testNewSessionToken, storedSession.SessionID)
				assert.Equal(t, testUserIDSession, storedSession.UserID)
				assert.Equal(t, testAuthIDSession, storedSession.AuthID)
				assert.Equal(t, newExpiry, storedSession.Expiry)
			}).Return(nil).Once()

		resp, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, testNewSessionToken, resp.NewSessionToken)
		assert.Equal(t, newExpiry, resp.NewExpiry)
		deps.mockSessionRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertExpectations(t)
	})

	t.Run("ErrorEmptyToken_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		_, err := deps.service.ExtendUserSession(ctx, "")
		require.Error(t, err)
		assert.EqualError(t, err, "current session token cannot be empty")
	})

	t.Run("ErrorGetSessionNotFound_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(nil, repository.ErrSessionNotFound).Once()

		_, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound)
		assert.Contains(t, err.Error(), "session not found or expired, cannot extend")
	})

	t.Run("ErrorSessionExpired_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		expiredSession := &models.Session{
			SessionID: testSessionToken,
			UserID:    testUserIDSession,
			AuthID:    testAuthIDSession,
			Expiry:    time.Now().UTC().Add(-1 * time.Hour),
		}
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(expiredSession, nil).Once()
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once() // Cleanup call

		_, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound) // Returns ErrSessionNotFound for expired
	})

	t.Run("ErrorGenerateTokenFails_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		genErr := errors.New("token generation failed")
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(currentValidSession, nil).Once()
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once()
		deps.mockTokenSvc.On("GenerateToken", testAuthIDSession).Return("", time.Time{}, genErr).Once()

		_, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, genErr)
		assert.Contains(t, err.Error(), "failed to generate new session token")
	})

	t.Run("ErrorStoreNewSessionFails_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		storeErr := errors.New("db store failed")
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(currentValidSession, nil).Once()
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once()
		deps.mockTokenSvc.On("GenerateToken", testAuthIDSession).Return(testNewSessionToken, newExpiry, nil).Once()
		deps.mockSessionRepo.On("StoreSession", ctx, mock.AnythingOfType("*models.Session")).Return(storeErr).Once()

		_, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, storeErr)
		assert.Contains(t, err.Error(), "failed to store new session")
	})

	t.Run("WarnDeleteOldSessionFailsButContinuesSuccessfully_ExtendUserSession", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deleteErr := errors.New("failed to delete old session but not critical")

		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(currentValidSession, nil).Once()
		// DeleteSession returns an error that is not ErrSessionNotFound, should be logged as WARN and continue
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(deleteErr).Once()
		deps.mockTokenSvc.On("GenerateToken", testAuthIDSession).Return(testNewSessionToken, newExpiry, nil).Once()
		deps.mockSessionRepo.On("StoreSession", ctx, mock.AnythingOfType("*models.Session")).Return(nil).Once()

		resp, err := deps.service.ExtendUserSession(ctx, testSessionToken)
		require.NoError(t, err) // Overall operation should succeed
		require.NotNil(t, resp)
		assert.Equal(t, testNewSessionToken, resp.NewSessionToken)

		// All mocks should have been called
		deps.mockSessionRepo.AssertExpectations(t)
		deps.mockTokenSvc.AssertExpectations(t)
	})
}

func TestSessionService_VerifySessionToken(t *testing.T) {
	ctx := context.Background()
	validExpiry := time.Now().UTC().Add(1 * time.Hour)
	sessionFromRepo := &models.Session{
		SessionID: testSessionToken,
		UserID:    testUserIDSession,
		Expiry:    validExpiry,
	}

	t.Run("Success_VerifySessionToken", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(sessionFromRepo, nil).Once()

		resp, err := deps.service.VerifySessionToken(ctx, testSessionToken)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.IsValid)
		assert.Equal(t, testSessionToken, resp.SessionID)
		assert.Equal(t, testUserIDSession, resp.UserID)
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("ErrorEmptyToken_VerifySessionToken", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		_, err := deps.service.VerifySessionToken(ctx, "")
		require.Error(t, err)
		assert.EqualError(t, err, "session token cannot be empty")
	})

	t.Run("ErrorSessionNotFoundInRepo_VerifySessionToken", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(nil, repository.ErrSessionNotFound).Once()

		_, err := deps.service.VerifySessionToken(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound)
		assert.Contains(t, err.Error(), "session not found or invalIDated")
	})

	t.Run("ErrorRepoFailure_VerifySessionToken", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		repoErr := errors.New(genericErrMsg)
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(nil, repoErr).Once()

		_, err := deps.service.VerifySessionToken(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, repoErr)
		assert.Contains(t, err.Error(), "error verifying session")
	})

	t.Run("ErrorSessionExpired_VerifySessionToken", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		expiredSession := &models.Session{
			SessionID: testSessionToken,
			UserID:    testUserIDSession,
			Expiry:    time.Now().UTC().Add(-1 * time.Hour), // Expired
		}
		deps.mockSessionRepo.On("GetSession", ctx, testSessionToken).Return(expiredSession, nil).Once()
		deps.mockSessionRepo.On("DeleteSession", ctx, testSessionToken).Return(nil).Once() // Expect cleanup

		_, err := deps.service.VerifySessionToken(ctx, testSessionToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrSessionNotFound) // Specific error for expired
		assert.Contains(t, err.Error(), "session expired")
		deps.mockSessionRepo.AssertExpectations(t)
	})
}

func TestSessionService_SignOutUserSessions(t *testing.T) {
	ctx := context.Background()
	tokenToExclude := "exclude-this-token"

	userInfo := &models.UserInfo{
		ID:     testUserIDSession,
		AuthID: testAuthIDSession,
	}

	t.Run("Success_SignOutUserSessions_WithExclusion", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		expectedDeletedCount := int64(5)

		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthIDSession).Return(userInfo, nil).Once()
		deps.mockSessionRepo.On("DeleteUserSessions", ctx, testUserIDSession, tokenToExclude).Return(expectedDeletedCount, nil).Once()

		deletedCount, err := deps.service.SignOutUserSessions(ctx, testAuthIDSession, tokenToExclude)
		require.NoError(t, err)
		assert.Equal(t, expectedDeletedCount, deletedCount)
		deps.mockUserRepo.AssertExpectations(t)
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("Success_SignOutUserSessions_WithoutExclusion", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		expectedDeletedCount := int64(3)

		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthIDSession).Return(userInfo, nil).Once()
		deps.mockSessionRepo.On("DeleteUserSessions", ctx, testUserIDSession).Return(expectedDeletedCount, nil).Once() // No token to exclude

		deletedCount, err := deps.service.SignOutUserSessions(ctx, testAuthIDSession)
		require.NoError(t, err)
		assert.Equal(t, expectedDeletedCount, deletedCount)
		deps.mockUserRepo.AssertExpectations(t)
		deps.mockSessionRepo.AssertExpectations(t)
	})

	t.Run("ErrorEmptyAuthID_SignOutUserSessions", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		_, err := deps.service.SignOutUserSessions(ctx, "")
		require.Error(t, err)
		assert.EqualError(t, err, "userID cannot be empty") // The service currently says "userID" but it means authID
		deps.mockUserRepo.AssertNotCalled(t, "GetUserInfoByAuthID", mock.Anything, mock.Anything)
		deps.mockSessionRepo.AssertNotCalled(t, "DeleteUserSessions", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("ErrorGetUserInfoFails_SignOutUserSessions", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		repoErr := errors.New("failed to get user")
		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthIDSession).Return(nil, repoErr).Once()

		_, err := deps.service.SignOutUserSessions(ctx, testAuthIDSession, tokenToExclude)
		require.Error(t, err)
		// This assertion depends on the SignOutUserSessions method correctly handling and returning this error.
		// Assuming it's fixed to: return 0, fmt.Errorf("failed to get user info: %w", err)
		assert.ErrorIs(t, err, repoErr)
		assert.Contains(t, err.Error(), "failed to get user info")
		deps.mockUserRepo.AssertExpectations(t)
		deps.mockSessionRepo.AssertNotCalled(t, "DeleteUserSessions", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("ErrorDeleteUserSessionsFails_SignOutUserSessions", func(t *testing.T) {
		deps := setupSessionServiceTest(t)
		repoErr := errors.New("failed to delete sessions")
		deps.mockUserRepo.On("GetUserInfoByAuthID", ctx, testAuthIDSession).Return(userInfo, nil).Once()
		deps.mockSessionRepo.On("DeleteUserSessions", ctx, testUserIDSession, tokenToExclude).Return(int64(0), repoErr).Once()

		_, err := deps.service.SignOutUserSessions(ctx, testAuthIDSession, tokenToExclude)
		require.Error(t, err)
		assert.ErrorIs(t, err, repoErr)
		assert.Contains(t, err.Error(), "failed to sign out user sessions")
		deps.mockUserRepo.AssertExpectations(t)
		deps.mockSessionRepo.AssertExpectations(t)
	})
}
