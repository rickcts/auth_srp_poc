package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT generation
type JWTService struct {
	jwtSecret []byte
}

var _ JWTGenerator = (*JWTService)(nil)

// NewTokenService creates a TokenService
func NewTokenService(secret string) *JWTService {
	return &JWTService{jwtSecret: []byte(secret)}
}

// GenerateToken creates a new JWT for a user
func (s *JWTService) GenerateToken(authID string) (string, time.Time, error) {
	exp := time.Now().Add(time.Hour * 1) // Expiration time (1 hour)
	claims := jwt.MapClaims{
		"sub": authID,
		"iss": "scs-auth-server",
		"aud": "scs-client-app",
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, exp, nil
}
