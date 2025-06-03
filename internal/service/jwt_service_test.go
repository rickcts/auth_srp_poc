package service

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-jwt-secret"

func TestNewTokenService(t *testing.T) {
	service := NewTokenService(testSecret)
	require.NotNil(t, service, "NewTokenService should not return nil")
	assert.Equal(t, []byte(testSecret), service.jwtSecret, "jwtSecret was not initialized correctly")
}

func TestJWTService_GenerateToken(t *testing.T) {
	service := NewTokenService(testSecret)
	userID := int64(123)

	t.Run("Success", func(t *testing.T) {
		tokenString, expiry, err := service.GenerateToken(userID)

		require.NoError(t, err, "GenerateToken should not return an error")
		require.NotEmpty(t, tokenString, "Generated token string should not be empty")

		// Check expiry time (approx 1 hour from now)
		expectedExpiry := time.Now().Add(time.Hour * 1)
		assert.WithinDuration(t, expectedExpiry, expiry, 5*time.Second, "Expiry time is not approximately 1 hour from now")

		// Parse the token to verify claims
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Make sure that the alg is what we expect (HS256)
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(testSecret), nil
		})
		require.NoError(t, err, "Failed to parse generated token")
		require.NotNil(t, token, "Parsed token should not be nil")
		assert.True(t, token.Valid, "Generated token should be valid")

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok, "Token claims should be of type jwt.MapClaims")

		// Verify standard claims
		assert.Equal(t, fmt.Sprint(userID), claims["sub"], "Subject claim (sub) is incorrect")
		assert.Equal(t, "scs-auth-server", claims["iss"], "Issuer claim (iss) is incorrect")
		assert.Equal(t, "scs-client-app", claims["aud"], "Audience claim (aud) is incorrect")

		// Verify time-based claims (exp, iat, nbf)
		expClaim, ok := claims["exp"].(float64)
		require.True(t, ok, "Expiration claim (exp) should be a number")
		assert.EqualValues(t, expiry.Unix(), int64(expClaim), "Expiration claim (exp) does not match returned expiry")

		iatClaim, ok := claims["iat"].(float64)
		require.True(t, ok, "IssuedAt claim (iat) should be a number")
		assert.InDelta(t, time.Now().Unix(), int64(iatClaim), 5, "IssuedAt claim (iat) is not recent") // Allow 5s delta

		nbfClaim, ok := claims["nbf"].(float64)
		require.True(t, ok, "NotBefore claim (nbf) should be a number")
		assert.InDelta(t, time.Now().Unix(), int64(nbfClaim), 5, "NotBefore claim (nbf) is not recent") // Allow 5s delta
	})

	t.Run("UserIDZero", func(t *testing.T) {
		userIDZero := int64(0)
		tokenString, _, err := service.GenerateToken(userIDZero)
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(testSecret), nil
		})
		require.NoError(t, err)
		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)
		assert.Equal(t, strconv.FormatInt(userIDZero, 10), claims["sub"], "Subject claim for userID 0 is incorrect")
	})

	// Note: It's hard to make token.SignedString fail in a unit test if the secret is valid and non-empty,
	// as jwt.NewWithClaims and the signing process itself are quite robust.
	// The primary failure path for SignedString would be an invalid (e.g., nil or empty) secret,
	// which NewTokenService should ideally prevent or handle if secrets could be dynamic/invalid.
	// Given the current NewTokenService, this path isn't easily unit-testable for GenerateToken itself.
}
