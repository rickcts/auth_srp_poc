package models

import (
	"time"

	"github.com/tadglines/go-pkgs/crypto/srp"
)

// SRPRegisterRequest is the input for user registration
type SRPRegisterRequest struct {
	AuthID      string `json:"authId"`
	DisplayName string `json:"displayName"`
	Salt        string `json:"salt"`     // Hex encoded salt 's'
	Verifier    string `json:"verifier"` // Hex encoded verifier 'v'
}

type ActivateUserRequest struct {
	AuthID string `json:"authId"`
	Code   string `json:"code"`
}

// AuthIDRequest is the input for the first step of SRP auth
type AuthIDRequest struct {
	AuthID string `json:"authId"`
}

// SaltResponse is the server's response to step 1
type SaltResponse struct {
	Salt string `json:"s"` // Hex encoded salt
}

type AuthStep1Request struct {
	AuthID string `json:"authId"`
}

type AuthStep1Response struct {
	Salt    string `json:"s"` // Hex encoded salt
	ServerB string `json:"B"` // Hex encoded server ephemeral public value B
}

// AuthStep2Request is the client's response (proof) in step 2
type AuthStep2Request struct {
	ClientA       string `json:"clientA"` // Hex encoded client public value A
	AuthID        string `json:"authId"`
	ClientProofM1 string `json:"clientProofM1"` // Hex encoded client proof M1
}

// AuthStep3Response is the server's final response (proof and token)
type AuthStep3Response struct {
	ServerProofM2 string    `json:"serverProofM2"`
	SessionToken  string    `json:"sessionToken"`
	SessionExpiry time.Time `json:"sessionExpiryDate"`
}

// AuthSessionState holds temporary server-side state during SRP flow
type AuthSessionState struct {
	AuthID string
	B      []byte
	Salt   []byte
	Server *srp.ServerSession
	Expiry time.Time
}

type MobileLoginRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	AuthProvider string `json:"authProvider"`
}

// InitiatePasswordResetRequest is the input for starting the password reset process.
type InitiatePasswordResetRequest struct {
	AuthID string `json:"authId"` // Typically the user's email
}

// InitiatePasswordResetResponse contains the details for a password reset.
type InitiatePasswordResetResponse struct {
	AuthID    string    `json:"authId"`
	ResetCode string    `json:"resetCode"`
	Expiry    time.Time `json:"expiry"`
}

// CompletePasswordResetRequest is the input for completing the password reset process.
type CompletePasswordResetRequest struct {
	Token       string `json:"token"`       // The password reset token
	NewSalt     string `json:"newSalt"`     // Hex encoded new salt 's'
	NewVerifier string `json:"newVerifier"` // Hex encoded new verifier 'v'
}

// ValidatePasswordResetTokenRequest is the input for validating a password reset token.
type ValidatePasswordResetTokenRequest struct {
	Token string `json:"token"` // The password reset token (6-digit code)
}

// ValidatePasswordResetTokenResponse is the output after validating a password reset token.
type ValidatePasswordResetTokenResponse struct {
	IsValid bool   `json:"isValid"`
	AuthID  string `json:"authId,omitempty"` // AuthID associated with the token, if valid. Only populated if IsValid is true.
}

type InitiateChangePasswordResponse struct {
	Salt    string `json:"salt"`    // User's current salt
	ServerB string `json:"serverB"` // Server's public ephemeral 'B' for current password verification
}

// ConfirmChangePasswordRequest is sent by the client to confirm the password change.
// AuthID is implicit from the session token.
type ConfirmChangePasswordRequest struct {
	ClientA     string `json:"clientA"`     // Client's public ephemeral 'A' for current password
	ClientM1    string `json:"clientM1"`    // Client's proof M1 for current password
	NewSalt     string `json:"newSalt"`     // New salt for the new password
	NewVerifier string `json:"newVerifier"` // New verifier for the new password
}
