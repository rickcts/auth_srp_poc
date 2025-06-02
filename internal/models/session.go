package models

import (
	"time"
)

// Session represents an active user login session.
type Session struct {
	SessionID string         `json:"sessionId"` // Unique ID for this session (e.g., a secure random string or UUID)
	UserID    int64          `json:"userId"`    // The ID of the logged-in user
	Username  string         `json:"username"`  // The username (can be useful)
	CreatedAt time.Time      `json:"createdAt"` // When the session was created
	Expiry    time.Time      `json:"expiry"`    // When the session expires
	UserAgent string         `json:"userAgent"` // Client's User-Agent (optional, for security/auditing)
	IPAddress string         `json:"ipAddress"` // Client's IP Address (optional, for security/auditing)
	Data      map[string]any `json:"data"`      // For any other custom data (roles, etc.)
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.Expiry)
}

type ExtendedSessionResponse struct {
	NewSessionToken string    `json:"newSessionToken"`
	NewExpiry       time.Time `json:"newExpiry"`
}

type VerifyTokenResponse struct {
	SessionID string
	UserID    int64
	IsValid   bool
}
