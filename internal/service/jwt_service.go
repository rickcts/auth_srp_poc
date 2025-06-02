package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var _ JWTGenerator = (*JWTService)(nil)

// NewTokenService creates a TokenService
func NewTokenService(secret string) *JWTService {
	return &JWTService{jwtSecret: []byte(secret)}
}

// GenerateToken creates a new JWT for a user
func (s *JWTService) GenerateToken(userId int64) (string, time.Time, error) {
	exp := time.Now().Add(time.Hour * 1) // Expiration time (1 hour)
	claims := jwt.MapClaims{
		"sub": userId,            // Subject (standard claim)
		"iss": "scs-auth-server", // Issuer (standard claim)
		"aud": "scs-client-app",  // Audience (standard claim)
		"exp": exp,
		"iat": time.Now().Unix(), // Issued at
		"nbf": time.Now().Unix(), // Not before
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

func (s *JWTService) ValidateToken(tokenString string) (userId int64, claims map[string]interface{}, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return -1, nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return -1, nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return -1, nil, fmt.Errorf("invalid token claims")
	}
	userId, ok = claims["sub"].(int64)
	if !ok {
		return -1, nil, fmt.Errorf("invalid token claims")
	}
	return userId, claims, nil
}
