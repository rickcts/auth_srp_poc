package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
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
		oAuthConfig: cfg.OAuth["MICROSOFT"],
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
		log.Error().Err(err).Msg("Error exchanging OAuth code for token")
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	if !token.Valid() {
		log.Warn().Msg("Received invalid OAuth token after exchange")
		return nil, errors.New("received invalid token")
	}
	log.Info().Int("accessTokenLength", len(token.AccessToken)).Msg("OAuth token obtained successfully")
	return token, nil
}

// ExchangeCodeMobile exchanges the authorization code for an OAuth2 token using PKCE.
func (s *OAuthService) ExchangeCodeMobile(ctx context.Context, code, codeVerifier, tokenProvider string) (*oauth2.Token, error) {
	pkceOption := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	oauth2token, err := s.oAuthConfig.Exchange(ctx, code, pkceOption)
	if err != nil {
		log.Error().Err(err).Str("provider", tokenProvider).Msg("Error exchanging code for token (Mobile Flow)")
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	if !oauth2token.Valid() {
		log.Warn().Str("provider", tokenProvider).Msg("Received invalid token (Mobile Flow)")
		return nil, errors.New("received invalid token")
	}
	log.Info().Str("provider", tokenProvider).Int("accessTokenLength", len(oauth2token.AccessToken)).Msg("Token obtained successfully (Mobile Flow)")
	return oauth2token, nil
}

func (s *OAuthService) VerifyToken(ctx context.Context, oauth2Token *oauth2.Token, tokenProvider string) (*oidc.IDToken, error) {
	providerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", "9188040d-6c67-4c5b-b112-36a304b66dad")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Error().Err(err).Str("providerURL", providerURL).Msg("Failed to create OIDC provider")
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	config := &oidc.Config{
		ClientID: s.cfg.OAuth["MICROSOFT"].ClientID,
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Warn().Msg("ID token missing from OAuth token response")
		return nil, errors.New("id_token missing from response")
	}

	verifier := provider.Verifier(config)

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to verify ID token")
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}
	log.Info().Str("issuer", idToken.Issuer).Str("subject", idToken.Subject).Msg("ID Token Verified Successfully")

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
		log.Error().Err(err).Str("api", s.api).Msg("Error fetching user info from Graph API")
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Warn().Int("statusCode", resp.StatusCode).Str("body", string(bodyBytes)).Str("api", s.api).Msg("Error response from Graph API")
		return nil, fmt.Errorf("graph API request failed with status: %s", resp.Status)
	}

	var user models.OAuthUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Error().Err(err).Msg("Error decoding user info JSON from Graph API")
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	user.Audience = idToken.Audience[0]
	user.Subject = idToken.Subject

	authID := user.Audience + ":" + user.Subject // aud:sub
	authExtrasJSON, err := json.Marshal(map[string]string{"oid": user.ID})
	if err != nil {
		log.Error().Err(err).Str("authId", authID).Msg("Error marshaling auth extras for OAuth user")
		return nil, fmt.Errorf("failed to marshal auth extras: %w", err)
	}
	if _, err := s.userRepo.GetUserInfoByAuthID(context.Background(), authID); err != nil {
		log.Info().Str("authId", authID).Str("displayName", user.DisplayName).Str("provider", tokenProvider).Msg("User not found by OAuth ID, creating new user.")
		s.userRepo.CreateUser(context.Background(), authID, user.DisplayName, tokenProvider, string(authExtrasJSON))
	}

	return &user, nil
}
