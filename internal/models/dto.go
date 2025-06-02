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

// SaltRequest is the input for the first step of SRP auth
type SaltRequest struct {
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
	ClientA       string `json:"A"` // Hex encoded client public value A
	AuthID        string `json:"authId"`
	ClientProofM1 string `json:"M1"` // Hex encoded client proof M1
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

// ErrorResponse standard error format
type ErrorResponse struct {
	Error string `json:"error"`
}

type MobileLoginRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	AuthProvider string `json:"authProvider"`
}

// ChangePasswordRequest is the input for changing a user's password.
type ChangePasswordRequest struct {
	NewSalt     string `json:"newSalt"`     // Hex encoded new salt 's'
	NewVerifier string `json:"newVerifier"` // Hex encoded new verifier 'v'
}

// InitiatePasswordResetRequest is the input for starting the password reset process.
type InitiatePasswordResetRequest struct {
	AuthID string `json:"authId"` // Typically the user's email
}

// CompletePasswordResetRequest is the input for completing the password reset process.
type CompletePasswordResetRequest struct {
	Token       string `json:"token"`       // The password reset token
	NewSalt     string `json:"newSalt"`     // Hex encoded new salt 's'
	NewVerifier string `json:"newVerifier"` // Hex encoded new verifier 'v'
}
