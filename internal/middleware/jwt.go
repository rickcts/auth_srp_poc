package middleware

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Config struct to hold Microsoft Entra ID configuration
type MSAuthConfig struct {
	TenantID       string // Your Microsoft Entra ID Tenant ID
	ClientID       string // Your Application (client) ID
	JWKSURI        string // Usually "https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys"
	UserInfoURL    string // Usually "https://graph.microsoft.com/oidc/userinfo"
	ExpectedIssuer string // Usually "https://login.microsoftonline.com/{tenant-id}/v2.0"
}

var authConfig MSAuthConfig
var jwksCache jwk.Set

// fetchJWKS fetches the JWKS from Microsoft and caches it.
func fetchJWKS() error {
	log.Printf("Fetching JWKS from %s", authConfig.JWKSURI)
	set, err := jwk.Fetch(context.Background(), authConfig.JWKSURI)
	if err != nil {
		return fmt.Errorf("failed to fetch jwks: %w", err)
	}
	jwksCache = set
	log.Println("JWKS fetched and cached successfully.")
	return nil
}

// refreshJWKSPeriodically can be used to refresh JWKS in the background.
func refreshJWKSPeriodically(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		log.Println("Refreshing JWKS...")
		if err := fetchJWKS(); err != nil {
			log.Printf("Error refreshing JWKS: %v", err)
		}
	}
}

// AuthMiddleware validates the JWT token from the Authorization header.
func AuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing Authorization header",
		})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid Authorization header format. Expected 'Bearer <token>'",
		})
	}
	tokenString := parts[1]

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the kid (Key ID) from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found in token")
		}

		// Find the key in the cached JWKS
		key, found := jwksCache.LookupKeyID(kid)
		if !found {
			// Optionally, try to refresh JWKS if key not found
			log.Printf("Key ID %s not found in cache. Attempting to refresh JWKS.", kid)
			if err := fetchJWKS(); err != nil {
				log.Printf("Failed to refresh JWKS: %v", err)
				return nil, fmt.Errorf("failed to refresh jwks while looking for key id %s: %w", kid, err)
			}
			// Retry lookup after refresh
			key, found = jwksCache.LookupKeyID(kid)
			if !found {
				return nil, fmt.Errorf("key id %s not found in jwks even after refresh", kid)
			}
		}

		// Convert the jwk.Key to a crypto.PublicKey (e.g., *rsa.PublicKey)
		var rawKey any
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key from jwk: %w", err)
		}
		return rawKey, nil
	})

	if err != nil {
		log.Printf("Token parsing/validation error: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Invalid token",
			"details": err.Error(),
		})
	}

	if !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token is not valid",
		})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Failed to parse token claims",
		})
	}

	issuer, _ := claims.GetIssuer()
	if !strings.HasPrefix(issuer, "https://login.microsoftonline.com/") || !strings.HasSuffix(issuer, "/v2.0") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid issuer"})
	}

	if issuer != authConfig.ExpectedIssuer {
		log.Printf("Warning: Issuer mismatch. Expected: %s, Got: %s. This might be an issue for single-tenant config or a misconfiguration.", authConfig.ExpectedIssuer, issuer)
	}

	// Validate Audience (aud)
	validAudience := false
	audiences, err := claims.GetAudience()
	if err != nil {
		log.Printf("Error getting audience from claims: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid audience claim"})
	}

	for _, aud := range audiences {
		if aud == authConfig.ClientID {
			validAudience = true
			break
		}
		if aud == "api://"+authConfig.ClientID {
			validAudience = true
			break
		}
	}
	if !validAudience {
		log.Printf("Invalid audience. Expected %s or api://%s, Got: %v", authConfig.ClientID, authConfig.ClientID, audiences)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Invalid audience",
			"details": fmt.Sprintf("Expected %s, got %v", authConfig.ClientID, audiences),
		})
	}

	// Validate Expiration (exp)
	expirationTime, err := claims.GetExpirationTime()
	if err != nil || expirationTime == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid expiration time"})
	}
	if time.Now().Unix() > expirationTime.Unix() {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token has expired"})
	}

	// Validate Not Before (nbf)
	notBeforeTime, err := claims.GetNotBefore()
	if err != nil {
		// nbf can be optional, so don't fail if it's not there, but if it is, validate it.
		log.Printf("Could not get NotBefore claim: %v", err)
	}
	if notBeforeTime != nil && time.Now().Unix() < notBeforeTime.Unix() {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token not yet valid (nbf)"})
	}

	// Store claims and the raw token in context for later use in handlers
	c.Locals("userClaims", claims)
	c.Locals("accessToken", tokenString) // Store the raw token string

	return c.Next()
}
