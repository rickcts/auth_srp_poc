package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

// SignOut invalIDates a user's session.
func (s *SRPAuthService) SignOut(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return errors.New("session token cannot be empty")
	}

	log.Printf("[AuthService.SignOut] Attempting to sign out session with token: %s", sessionToken)
	err := s.sessionRepo.DeleteSession(ctx, sessionToken)
	if err != nil {
		// It's okay to be already expired or not found
		if errors.Is(err, repository.ErrSessionNotFound) {
			log.Printf("[AuthService.SignOut] Session token '%s' not found or already invalIDated. ConsIDered successful.", sessionToken)
			return nil
		}
		log.Printf("[AuthService.SignOut] ERROR: Failed to delete session for token '%s': %v", sessionToken, err)
		return fmt.Errorf("failed to sign out: %w", err)
	}

	log.Printf("[AuthService.SignOut] SUCCESS: Session invalIDated for token: %s", sessionToken)
	return nil
}

// ExtendUserSession valIdates an existing session token, issues a new one with a new expiry,
// and stores the new session.
func (s *SRPAuthService) ExtendUserSession(ctx context.Context, currentSessionToken string) (*models.ExtendedSessionResponse, error) {
	if currentSessionToken == "" {
		return nil, errors.New("current session token cannot be empty")
	}

	log.Printf("[AuthService.ExtendUserSession] Attempting to extend session for token: %s", currentSessionToken)

	currentSession, err := s.sessionRepo.GetSession(ctx, currentSessionToken)
	if err != nil {
		log.Printf("[AuthService.ExtendUserSession] ERROR: Failed to get current session for token '%s': %v", currentSessionToken, err)
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, fmt.Errorf("session not found or expired, cannot extend: %w", err)
		}
		return nil, fmt.Errorf("failed to retrieve current session: %w", err)
	}

	if currentSession.IsExpired() {
		log.Printf("[AuthService.ExtendUserSession] ERROR: Current session for token '%s' (User: %v) is expired.", currentSessionToken, currentSession.AuthID)
		// Proactively delete it if found expired here, though GetSession implementation should handle this.
		_ = s.sessionRepo.DeleteSession(ctx, currentSessionToken)
		return nil, repository.ErrSessionNotFound
	}

	authID := currentSession.AuthID
	userID := currentSession.UserID

	log.Printf("[AuthService.ExtendUserSession] Current session for token '%s' (User: %v) is valid. Proceeding with extension.", currentSessionToken, authID)

	err = s.sessionRepo.DeleteSession(ctx, currentSessionToken)
	if err != nil && !errors.Is(err, repository.ErrSessionNotFound) {
		log.Printf("[AuthService.ExtendUserSession] WARN: Failed to delete old session for token '%s' (User: %v): %v", currentSessionToken, authID, err)
	}

	newSessionToken, newExpiry, err := s.tokenSvc.GenerateToken(authID)
	if err != nil {
		log.Printf("[AuthService.ExtendUserSession] ERROR: Failed to generate new token for user '%v': %v", authID, err)
		return nil, fmt.Errorf("failed to generate new session token: %w", err)
	}

	newSession := &models.Session{
		SessionID: newSessionToken,
		AuthID:    authID,
		UserID:    userID,
		Expiry:    newExpiry,
	}

	if err := s.sessionRepo.StoreSession(ctx, newSession); err != nil {
		log.Printf("[AuthService.ExtendUserSession] ERROR: Failed to store new session for user '%v' (New Token: %s): %v", authID, newSessionToken, err)
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

	log.Printf("[AuthService.ExtendUserSession] SUCCESS: Session extended for user '%v'. New Token: %s, New Expiry: %v", authID, newSessionToken, newExpiry)

	return &models.ExtendedSessionResponse{
		NewSessionToken: newSessionToken,
		NewExpiry:       newExpiry,
	}, nil
}

func (s *SRPAuthService) VerifySessionToken(ctx context.Context, sessionTokenID string) (*models.VerifyTokenResponse, error) {
	if sessionTokenID == "" {
		return nil, errors.New("session token cannot be empty")
	}

	log.Printf("[AuthService.VerifySessionToken] Attempting to verify session token from store: %s", sessionTokenID)

	session, err := s.sessionRepo.GetSession(ctx, sessionTokenID)
	if err != nil {
		log.Printf("[AuthService.VerifySessionToken] Failed to get session from store for token '%s': %v", sessionTokenID, err)
		if errors.Is(err, repository.ErrSessionNotFound) {
			return nil, fmt.Errorf("session not found or invalIDated: %w", err)
		}
		return nil, fmt.Errorf("error verifying session: %w", err)
	}

	if session.IsExpired() { // Check server-sIDe expiry
		log.Printf("[AuthService.VerifySessionToken] Session token '%s' (User: %v) found in store but is expired.", sessionTokenID, session.UserID)
		_ = s.sessionRepo.DeleteSession(ctx, sessionTokenID) // Clean up expired session
		return nil, fmt.Errorf("session expired: %w", repository.ErrSessionNotFound)
	}

	log.Printf("[AuthService.VerifySessionToken] SUCCESS: Session token is valid for UserID: %v", session.UserID)
	return &models.VerifyTokenResponse{
		SessionID: sessionTokenID,
		UserID:    session.UserID,
		IsValid:   true,
	}, nil
}

// SignOutUserSessions invalidates all sessions for a given user, optionally excluding some.
func (s *SRPAuthService) SignOutUserSessions(ctx context.Context, authID string, currentSessionTokenToExclude ...string) (int64, error) {
	if authID == "" {
		return 0, errors.New("userID cannot be empty")
	}
	user, err := s.userRepo.GetUserInfoByAuthID(ctx, authID)
	if err != nil {

	}
	userID := user.ID

	log.Printf("[AuthService.SignOutUserSessions] Attempting to sign out all sessions for UserID: %v, excluding %d tokens", userID, len(currentSessionTokenToExclude))

	deletedCount, err := s.sessionRepo.DeleteUserSessions(ctx, userID, currentSessionTokenToExclude...)
	if err != nil {
		log.Printf("[AuthService.SignOutUserSessions] ERROR: Failed to delete sessions for UserID '%v': %v", userID, err)
		return 0, fmt.Errorf("failed to sign out user sessions: %w", err)
	}

	log.Printf("[AuthService.SignOutUserSessions] SUCCESS: Deleted %d sessions for UserID: %v", deletedCount, userID)
	return deletedCount, nil
}
