package ent_repo_test

import (
	"context"
	"testing"

	"github.com/rickcts/srp/ent"
	"github.com/rickcts/srp/internal/repository"
	ent_repo "github.com/rickcts/srp/internal/repository/ent"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntUserRepository(t *testing.T) {
	client, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()

	// Run the auto migration tool.
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("failed creating schema resources: %v", err)
	}
	repo := ent_repo.NewEntUserRepository(client)

	username := "testuser"
	salt := "somesalt"
	verifier := "someverifier"

	t.Run("CreateAndGetUser", func(t *testing.T) {
		err := repo.CreateUserCreds(ctx, username, salt, verifier)
		require.NoError(t, err)

		retSalt, retVerifier, err := repo.GetUserCredsByUsername(ctx, username)
		require.NoError(t, err)
		assert.Equal(t, salt, retSalt)
		assert.Equal(t, verifier, retVerifier)
	})

	t.Run("GetUserNotFound", func(t *testing.T) {
		_, _, err := repo.GetUserCredsByUsername(ctx, "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})

	t.Run("CreateUserExists", func(t *testing.T) {
		err := repo.CreateUserCreds(ctx, username, "anothersalt", "anotherverifier")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrUserExists)
	})
}
