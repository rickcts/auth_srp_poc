// internal/repository/memory/state_memory_test.go
package memory_test

import (
	"testing"
	"time"

	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
	"github.com/rickcts/srp/internal/repository/memory"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStateRepository(t *testing.T) {
	repo := memory.NewMemoryStateRepository()

	authID := "testuser"
	state := models.AuthSessionState{
		Username: authID,
		Salt:     []byte("somesalt"),
		B:        []byte("someB"),
		Expiry:   time.Now().Add(5 * time.Minute),
	}

	t.Run("StoreAndGetState", func(t *testing.T) {
		err := repo.StoreAuthState(authID, state)
		require.NoError(t, err)

		retState, err := repo.GetAuthState(authID)
		require.NoError(t, err)
		require.NotNil(t, retState)
		assert.Equal(t, state.Username, retState.Username)
		assert.Equal(t, state.Salt, retState.Salt)
		assert.Equal(t, state.B, retState.B)
		// Don't compare Expiry directly due to potential minor time differences
		assert.False(t, retState.Expiry.IsZero())
	})

	t.Run("GetStateNotFound", func(t *testing.T) {
		_, err := repo.GetAuthState("nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
	})

	t.Run("GetStateExpired", func(t *testing.T) {
		expiredAuthID := "expireduser"
		expiredState := models.AuthSessionState{
			Username: expiredAuthID,
			Expiry:   time.Now().Add(-1 * time.Minute), // Expired
		}
		err := repo.StoreAuthState(expiredAuthID, expiredState)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = repo.GetAuthState(expiredAuthID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)

	})

	t.Run("DeleteState", func(t *testing.T) {
		deleteAuthID := "deleteuser"
		deleteState := models.AuthSessionState{
			Username: deleteAuthID,
			Expiry:   time.Now().Add(5 * time.Minute),
		}
		err := repo.StoreAuthState(deleteAuthID, deleteState)
		require.NoError(t, err)

		err = repo.DeleteAuthState(deleteAuthID)
		require.NoError(t, err)

		_, err = repo.GetAuthState(deleteAuthID)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrStateNotFound)
	})
}
