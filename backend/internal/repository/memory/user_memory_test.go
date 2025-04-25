// internal/repository/memory/user_memory_test.go
package memory_test

import (
	"context"
	"testing"

	"github.com/rickcts/srp/internal/repository"
	"github.com/rickcts/srp/internal/repository/memory"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryUserRepository(t *testing.T) {
	repo := memory.NewMemoryUserRepository()

	username := "testuser"
	salt := "somesalt"
	verifier := "someverifier"

	t.Run("CreateAndGetUser", func(t *testing.T) {
		err := repo.CreateUserCreds(context.Background(), username, salt, verifier)
		require.NoError(t, err)

		retSalt, retVerifier, err := repo.GetUserCredsByUsername(context.Background(), username)
		require.NoError(t, err)
		assert.Equal(t, salt, retSalt)
		assert.Equal(t, verifier, retVerifier)
	})

	t.Run("GetUserNotFound", func(t *testing.T) {
		_, _, err := repo.GetUserCredsByUsername(context.Background(), "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})

	t.Run("CreateUserExists", func(t *testing.T) {
		err := repo.CreateUserCreds(context.Background(), username, "anothersalt", "anotherverifier")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrUserExists)
	})
}
