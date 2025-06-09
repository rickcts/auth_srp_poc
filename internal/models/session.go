package models

import (
	"time"
)

// Session represents an active user login session.
type Session struct {
	SessionID   string    `json:"sessionId"`   // Unique ID for this session (e.g., a secure random string or UUID)
	UserID      int64     `json:"userId"`      // The ID of the user associated with this session
	AuthID      string    `json:"authId"`      // The ID of the logged-in method
	DisplayName string    `json:"displayName"` // The displayName
	Host        string    `json:"host"`        // The host of the the client
	UserAgent   string    `json:"userAgent"`   // The useragent of the request
	CreatedAt   time.Time `json:"createdAt"`   // When the session was created
	Expiry      time.Time `json:"expiry"`      // When the session expires
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.Expiry)
}

type GetUserSessionsResponse struct {
	Sessions []*Session `json:"sessions"`
}

type ExtendedSessionResponse struct {
	NewSessionToken string    `json:"newSessionToken"`
	NewExpiry       time.Time `json:"newExpiry"`
}

type VerifyTokenResponse struct {
	SessionID string `json:"sessionId"`
	UserID    int64  `json:"userId"`
	IsValid   bool   `json:"isValid"`
}
