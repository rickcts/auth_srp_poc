package repository

import (
	"context"
	"fmt" // Added fmt

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
)

// StateRepository handles temporary SRP session state
type StateRepository interface {
	StoreAuthState(ctx context.Context, authID string, state models.AuthSessionState) error
	GetAuthState(ctx context.Context, authID string) (*models.AuthSessionState, error)
	DeleteAuthState(ctx context.Context, authID string) error
}

var ErrStateNotFound = fmt.Errorf("auth state not found or expired")
