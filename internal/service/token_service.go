package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var _ TokenGenerator = (*TokenService)(nil)

// NewTokenService creates a TokenService
func NewTokenService(secret string) *TokenService {
	return &TokenService{jwtSecret: []byte(secret)}
}

// GenerateToken creates a new JWT for a user
func (s *TokenService) GenerateToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,                             // Subject (standard claim)
		"iss": "my-srp-auth-server",                 // Issuer (standard claim)
		"aud": "my-client-app",                      // Audience (standard claim)
		"exp": time.Now().Add(time.Hour * 1).Unix(), // Expiration time (1 hour)
		"iat": time.Now().Unix(),                    // Issued at
		"nbf": time.Now().Unix(),                    // Not before
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (s *TokenService) ValidateToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	username, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	return username, nil
}
