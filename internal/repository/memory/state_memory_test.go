// internal/repository/memory/state_memory_test.go
package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/memory"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStateRepository(t *testing.T) {
	repo := memory.NewMemoryStateRepository()

	authID := "testuser"
	state := models.AuthSessionState{
		AuthID: authID,
		Salt:   []byte("somesalt"),
		B:      []byte("someB"),
		Expiry: time.Now().UTC().Add(5 * time.Minute),
	}
	ctx := context.Background()

	t.Run("StoreAndGetState", func(t *testing.T) {
		err := repo.StoreAuthState(ctx, authID, state)
		require.NoError(t, err)

		retState, err := repo.GetAuthState(ctx, authID)
		require.NoError(t, err)
		require.NotNil(t, retState)
		assert.Equal(t, state.AuthID, retState.AuthID)
		assert.Equal(t, state.Salt, retState.Salt)
		assert.Equal(t, state.B, retState.B)
		assert.False(t, retState.Expiry.IsZero())
	})

	t.Run("GetStateNotFound", func(t *testing.T) {
		_, err := repo.GetAuthState(ctx, "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
	})

	t.Run("GetStateExpired", func(t *testing.T) {
		expiredAuthID := "expireduser"
		expiredState := models.AuthSessionState{
			AuthID: expiredAuthID,
			Expiry: time.Now().UTC().Add(-1 * time.Minute), // Expired
		}
		err := repo.StoreAuthState(ctx, expiredAuthID, expiredState)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = repo.GetAuthState(ctx, expiredAuthID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)

	})

	t.Run("DeleteState", func(t *testing.T) {
		deleteAuthID := "deleteuser"
		deleteState := models.AuthSessionState{
			AuthID: deleteAuthID,
			Expiry: time.Now().UTC().Add(5 * time.Minute),
		}
		err := repo.StoreAuthState(ctx, deleteAuthID, deleteState)
		require.NoError(t, err)

		err = repo.DeleteAuthState(ctx, deleteAuthID)
		require.NoError(t, err)

		_, err = repo.GetAuthState(ctx, deleteAuthID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
	})
}
