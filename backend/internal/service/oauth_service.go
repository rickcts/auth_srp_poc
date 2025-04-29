package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/rickcts/srp/internal/config"
	"github.com/rickcts/srp/internal/models"
	"golang.org/x/oauth2"
)

// NewMSOAuthService creates a new instance of OAuthService
func NewMSOAuthService(cfg *config.Config) *OAuthService {
	return &OAuthService{
		Config:      cfg,
		OAuthConfig: cfg.OAuthProviders["microsoft"],
		API:         "https://graph.microsoft.com/v1.0/me",
	}
}

// GetAuthCodeURL generates the URL for the Microsoft login page
func (s *OAuthService) GetAuthCodeURL(state string) string {
	return s.OAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges the authorization code for an OAuth2 token
func (s *OAuthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := s.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("Error exchanging code for token: %v\n", err)
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	if !token.Valid() {
		log.Println("Received invalid token")
		return nil, errors.New("received invalid token")
	}
	log.Printf("Token obtained successfully. Access Token length: %d\n", len(token.AccessToken))
	return token, nil
}

// GetUserInfo uses the access token to fetch user details from Microsoft Graph API
func (s *OAuthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*models.OAuthUser, error) {
	client := s.OAuthConfig.Client(ctx, token) // Creates an HTTP client using the token

	resp, err := client.Get(s.API)
	if err != nil {
		log.Printf("Error fetching user info from Graph API: %v\n", err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Error response from Graph API: Status=%d, Body=%s\n", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("graph API request failed with status: %s", resp.Status)
	}

	var user models.OAuthUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Printf("Error decoding user info JSON: %v\n", err)
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Sometimes email is in userPrincipalName if 'mail' is null
	if user.Email == "" {
		// Need to request userPrincipalName field if needed, requires scope User.ReadBasic.All or User.Read.All potentially
		// For simplicity, we'll leave it potentially empty based on the basic /me response
		log.Println("User email (mail attribute) is empty.")
	}

	log.Printf("User info fetched successfully: ID=%s, Name=%s, Email=%s\n", user.ID, user.DisplayName, user.Email)
	return &user, nil
}
