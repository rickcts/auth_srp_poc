package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/rs/zerolog/log"
)

type SessionService struct {
	sessionRepo repository.SessionRepository
	userRepo    repository.UserRepository
	tokenSvc    JWTGenerator
}

var _ SessionGenerator = (*SessionService)(nil)

// NewTokenService creates a TokenService
func NewSessionService(sessionRepo repository.SessionRepository, userRepo repository.UserRepository, tokenSvc JWTGenerator) *SessionService {
	return &SessionService{sessionRepo: sessionRepo, userRepo: userRepo, tokenSvc: tokenSvc}
}

// SignOut invalIDates a user's session.
func (s *SessionService) SignOut(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return errors.New("session token cannot be empty")
	}

	log.Info().Str("sessionTokenPrefix", безопасныйПрефикс(sessionToken, 10)).Msg("Attempting to sign out session")
	err := s.sessionRepo.DeleteSession(ctx, sessionToken)
	if err != nil {
		// It's okay to be already expired or not found
		if errors.Is(err, repository.ErrSessionNotFound) {
			log.Info().Str("sessionTokenPrefix", безопасныйПрефикс(sessionToken, 10)).Msg("Session token not found or already invalidated during sign out. Considered successful.")
			return nil
		}
		log.Error().Err(err).Str("sessionTokenPrefix", безопасныйПрефикс(sessionToken, 10)).Msg("Failed to delete session during sign out")
		return fmt.Errorf("failed to sign out: %w", err)
	}

	log.Info().Str("sessionTokenPrefix", безопасныйПрефикс(sessionToken, 10)).Msg("Session invalidated successfully")
	return nil
}

func (s *SessionService) GetUserSessions(ctx context.Context, authID string) (*models.GetUserSessionsResponse, error) {
	if authID == "" {
		return nil, errors.New("authID cannot be empty")
	}

	userInfo, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Warn().Err(err).Str("authId", authID).Msg("Failed to get user info for GetUserSessions")
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	userID := userInfo.ID

	log.Info().Int64("userId", userID).Msg("Attempting to get user sessions")

	sessions, err := s.sessionRepo.GetSessions(ctx, userID)
	if err != nil {
		log.Error().Err(err).Int64("userId", userID).Msg("Failed to get user sessions from repository")
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	log.Info().Int("sessionCount", len(sessions)).Int64("userId", userID).Msg("Successfully retrieved user sessions")
	return &models.GetUserSessionsResponse{Sessions: sessions}, nil
}

// ExtendUserSession valIdates an existing session token, issues a new one with a new expiry,
// and stores the new session.
func (s *SessionService) ExtendUserSession(ctx context.Context, currentSessionToken string) (*models.ExtendedSessionResponse, error) {
	if currentSessionToken == "" {
		return nil, errors.New("current session token cannot be empty")
	}

	log.Info().Str("currentTokenPrefix", безопасныйПрефикс(currentSessionToken, 10)).Msg("Attempting to extend user session")

	currentSession, err := s.sessionRepo.GetSession(ctx, currentSessionToken)
	if err != nil {
		log.Warn().Err(err).Str("currentTokenPrefix", безопасныйПрефикс(currentSessionToken, 10)).Msg("Failed to get current session for extension")
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, fmt.Errorf("session not found or expired, cannot extend: %w", err)
		}
		return nil, fmt.Errorf("failed to retrieve current session: %w", err)
	}

	if currentSession.IsExpired() {
		log.Warn().Str("currentTokenPrefix", безопасныйПрефикс(currentSessionToken, 10)).Str("authId", currentSession.AuthID).Msg("Current session is expired, cannot extend.")
		// Proactively delete it if found expired here, though GetSession implementation should handle this.
		_ = s.sessionRepo.DeleteSession(ctx, currentSessionToken)
		return nil, repository.ErrSessionNotFound
	}

	authID := currentSession.AuthID
	userID := currentSession.UserID

	log.Info().Str("currentTokenPrefix", безопасныйПрефикс(currentSessionToken, 10)).Str("authId", authID).Msg("Current session is valid. Proceeding with extension.")

	err = s.sessionRepo.DeleteSession(ctx, currentSessionToken)
	if err != nil && !errors.Is(err, repository.ErrSessionNotFound) {
		log.Warn().Err(err).Str("currentTokenPrefix", безопасныйПрефикс(currentSessionToken, 10)).Str("authId", authID).Msg("Failed to delete old session during extension, but continuing.")
	}

	newSessionToken, newExpiry, err := s.tokenSvc.GenerateToken(authID)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to generate new token for session extension")
		return nil, fmt.Errorf("failed to generate new session token: %w", err)
	}

	newSession := &models.Session{
		SessionID: newSessionToken,
		AuthID:    authID,
		UserID:    userID,
		Expiry:    newExpiry,
	}

	if err := s.sessionRepo.StoreSession(ctx, newSession); err != nil {
		log.Error().Err(err).Str("authId", authID).Str("newTokenPrefix", безопасныйПрефикс(newSessionToken, 10)).Msg("Failed to store new session during extension")
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

	log.Info().Str("authId", authID).Str("newTokenPrefix", безопасныйПрефикс(newSessionToken, 10)).Time("newExpiry", newExpiry).Msg("Session extended successfully")

	return &models.ExtendedSessionResponse{
		NewSessionToken: newSessionToken,
		NewExpiry:       newExpiry,
	}, nil
}

func (s *SessionService) VerifySessionToken(ctx context.Context, sessionTokenID string) (*models.VerifyTokenResponse, error) {
	if sessionTokenID == "" {
		return nil, errors.New("session token cannot be empty")
	}

	log.Info().Str("sessionTokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Attempting to verify session token from store")

	session, err := s.sessionRepo.GetSession(ctx, sessionTokenID)
	if err != nil {
		log.Warn().Err(err).Str("sessionTokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Failed to get session from store for verification")
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, fmt.Errorf("session not found or invalIDated: %w", err)
		}
		return nil, fmt.Errorf("error verifying session: %w", err)
	}

	if session.IsExpired() { // Check server-sIDe expiry
		log.Warn().Str("sessionTokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Int64("userId", session.UserID).Msg("Session token found in store but is expired.")
		_ = s.sessionRepo.DeleteSession(ctx, sessionTokenID) // Clean up expired session
		return nil, fmt.Errorf("session expired: %w", repository.ErrSessionNotFound)
	}

	log.Info().Int64("userId", session.UserID).Str("sessionTokenPrefix", безопасныйПрефикс(sessionTokenID, 10)).Msg("Session token is valid")
	return &models.VerifyTokenResponse{
		SessionID: sessionTokenID,
		UserID:    session.UserID,
		IsValid:   true,
	}, nil
}

// SignOutUserSessions invalidates all sessions for a given user, optionally excluding some.
func (s *SessionService) SignOutUserSessions(ctx context.Context, authID string, currentSessionTokenToExclude ...string) (int64, error) {
	if authID == "" {
		return 0, errors.New("userID cannot be empty")
	}
	user, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Failed to get user info for SignOutUserSessions")
		return 0, fmt.Errorf("failed to get user info: %w", err)
	}
	userID := user.ID // Now safe to access user.ID

	log.Info().Int64("userId", userID).Int("excludeCount", len(currentSessionTokenToExclude)).Msg("Attempting to sign out all sessions for user")

	deletedCount, err := s.sessionRepo.DeleteUserSessions(ctx, userID, currentSessionTokenToExclude...)
	if err != nil {
		log.Error().Err(err).Int64("userId", userID).Msg("Failed to delete user sessions from repository")
		return 0, fmt.Errorf("failed to sign out user sessions: %w", err)
	}

	log.Info().Int64("deletedCount", deletedCount).Int64("userId", userID).Msg("Successfully signed out user sessions")
	return deletedCount, nil
}

func безопасныйПрефикс(s string, length int) string {
	if len(s) > length {
		return s[:length]
	}
	return s
}
