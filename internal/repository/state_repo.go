package repository

import (
	"fmt" // Added fmt

	"github.com/rickcts/srp/internal/models"
)

// StateRepository handles temporary SRP session state
type StateRepository interface {
	StoreAuthState(authID string, state models.AuthSessionState) error
	GetAuthState(authID string) (*models.AuthSessionState, error)
	DeleteAuthState(authID string) error
}

var ErrStateNotFound = fmt.Errorf("auth state not found or expired")
