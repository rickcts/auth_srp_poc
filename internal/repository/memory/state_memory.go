package memory

import (
	"context"
	"sync"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

// MemoryStateRepository implements StateRepository in memory (NOT FOR PRODUCTION)
type MemoryStateRepository struct {
	states map[string]models.AuthSessionState
	mutex  sync.RWMutex
}

func NewMemoryStateRepository() repository.StateRepository {
	return &MemoryStateRepository{
		states: make(map[string]models.AuthSessionState),
	}
}

func (r *MemoryStateRepository) StoreAuthState(ctx context.Context, authID string, state models.AuthSessionState) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.states[authID] = state
	return nil
}

func (r *MemoryStateRepository) GetAuthState(ctx context.Context, authID string) (*models.AuthSessionState, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	state, exists := r.states[authID]
	if !exists || time.Now().UTC().After(state.Expiry) {
		// Clean up expired state if found
		if exists {
			go r.DeleteAuthState(ctx, authID) // Delete in background
		}
		return nil, repository.ErrStateNotFound
	}
	return &state, nil
}

func (r *MemoryStateRepository) DeleteAuthState(ctx context.Context, authID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.states, authID)
	return nil
}
