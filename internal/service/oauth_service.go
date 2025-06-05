package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OAuthService handles interactions with the OAuth2 provider
type OAuthService struct {
	userRepo    repository.UserRepository
	cfg         *config.Config
	oAuthConfig *oauth2.Config
	api         string
}

// NewMSOAuthService creates a new instance of OAuthService
func NewMSOAuthService(cfg *config.Config, userRepo repository.UserRepository) *OAuthService {
	return &OAuthService{
		userRepo:    userRepo,
		cfg:         cfg,
		oAuthConfig: cfg.OAuthProviders["MICROSOFT"],
		api:         "https://graph.microsoft.com/v1.0/me",
	}
}

// GetAuthCodeURL generates the URL for the Microsoft login page
func (s *OAuthService) GetAuthCodeURL(state string) string {
	return s.oAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges the authorization code for an OAuth2 token
func (s *OAuthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := s.oAuthConfig.Exchange(ctx, code)
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

// ExchangeCodeMobile exchanges the authorization code for an OAuth2 token using PKCE.
func (s *OAuthService) ExchangeCodeMobile(ctx context.Context, code, codeVerifier, tokenProvider string) (*oauth2.Token, error) {
	pkceOption := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	oauth2token, err := s.oAuthConfig.Exchange(ctx, code, pkceOption)
	if err != nil {
		log.Printf("Error exchanging code for token (Mobile Flow): %v\n", err)
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	if !oauth2token.Valid() {
		log.Println("Received invalid token (Mobile Flow)")
		return nil, errors.New("received invalid token")
	}

	log.Printf("Token obtained successfully (Mobile Flow). Access Token length: %d\n", len(oauth2token.AccessToken))
	return oauth2token, nil
}

func (s *OAuthService) VerifyToken(ctx context.Context, oauth2Token *oauth2.Token, tokenProvider string) (*oidc.IDToken, error) {
	providerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", "9188040d-6c67-4c5b-b112-36a304b66dad")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Printf("Failed to create OIDC provider: %v\n", err)
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	config := &oidc.Config{
		ClientID: s.cfg.OAuthProviders["MICROSOFT"].ClientID,
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Println("ID token missing from token response")
		return nil, errors.New("id_token missing from response")
	}

	verifier := provider.Verifier(config)

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v\n", err)
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	log.Printf("ID Token Verified Successfully! Issuer: %s, Subject: %s\n", idToken.Issuer, idToken.Subject)

	return idToken, nil
}

// GetUserInfo uses the access token to fetch user details from Microsoft Graph API
func (s *OAuthService) ProcessUserInfo(ctx context.Context, oauth2token *oauth2.Token, tokenProvider string) (*models.OAuthUser, error) {
	idToken, err := s.VerifyToken(ctx, oauth2token, tokenProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	client := s.oAuthConfig.Client(ctx, oauth2token)

	resp, err := client.Get(s.api)
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
	user.Audience = idToken.Audience[0]
	user.Subject = idToken.Subject

	authId := user.Audience + ":" + user.Subject // aud:sub
	authExtrasJSON, err := json.Marshal(map[string]string{"oid": user.ID})
	if err != nil {
		log.Printf("Error marshaling auth extras: %v\n", err)
		return nil, fmt.Errorf("failed to marshal auth extras: %w", err)
	}
	if _, err := s.userRepo.GetUserInfoByAuthID(context.Background(), authId); err != nil {
		s.userRepo.CreateUser(context.Background(), authId, user.DisplayName, tokenProvider, string(authExtrasJSON))
	}

	return &user, nil
}
