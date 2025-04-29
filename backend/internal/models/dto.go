package models

import (
	"time"

	"github.com/tadglines/go-pkgs/crypto/srp"
)

// SRPRegisterRequest is the input for user registration
type SRPRegisterRequest struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`     // Hex encoded salt 's'
	Verifier string `json:"verifier"` // Hex encoded verifier 'v'
}

// SaltRequest is the input for the first step of SRP auth
type SaltRequest struct {
	Username string `json:"username"`
}

// SaltResponse is the server's response to step 1
type SaltResponse struct {
	Salt string `json:"s"` // Hex encoded salt
}

type AuthStep1Request struct {
	Username string `json:"username"`
}

type AuthStep1Response struct {
	Salt    string `json:"s"` // Hex encoded salt
	ServerB string `json:"B"` // Hex encoded server ephemeral public value B
}

// AuthStep2Request is the client's response (proof) in step 2
type AuthStep2Request struct {
	ClientA       string `json:"A"` // Hex encoded client public value A
	Username      string `json:"username"`
	ClientProofM1 string `json:"M1"` // Hex encoded client proof M1
}

// AuthStep3Response is the server's final response (proof and token)
type AuthStep3Response struct {
	ServerProofM2 string `json:"M2"`    // Hex encoded server proof M2
	SessionToken  string `json:"token"` // e.g., JWT
}

// AuthSessionState holds temporary server-side state during SRP flow
type AuthSessionState struct {
	Username string
	B        []byte
	Salt     []byte
	Server   *srp.ServerSession
	Expiry   time.Time
}

// ErrorResponse standard error format
type ErrorResponse struct {
	Error string `json:"error"`
}
