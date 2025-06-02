package ent_repo_test

import (
	"context"
	"testing"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/enttest"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/user"
	ent_userauth "github.com/SimpnicServerTeam/scs-aaa-server/ent/userauth"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	ent_repo "github.com/SimpnicServerTeam/scs-aaa-server/internal/repository/ent"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRepo sets up an in-memory SQLite database for testing.
// It uses enttest.Open, which handles schema creation and client cleanup.
func newTestRepo(t *testing.T) (context.Context, *ent.Client, repository.UserRepository) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	repo := ent_repo.NewEntUserRepository(client)
	return context.Background(), client, repo
}

func TestEntUserRepository(t *testing.T) {
	// Test data
	AuthID1 := "user1@example.com"
	displayName1 := "User One"
	authProvider1 := "SRP6"
	extras1 := map[string]string{
		"salt":     "salt1",
		"verifier": "verifier1",
	}

	AuthID2 := "user2@example.com"
	displayName2 := "User Two"

	t.Run("CreateAndGetUser", func(t *testing.T) {
		ctx, _, repo := newTestRepo(t)

		err := repo.CreateUser(ctx, AuthID1, displayName1, authProvider1, extras1)
		require.NoError(t, err)

		userInfo, err := repo.GetUserInfoByAuthID(ctx, AuthID1)
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.NotZero(t, userInfo.ID)
		assert.Equal(t, displayName1, userInfo.DisplayName)
		assert.Equal(t, AuthID1, userInfo.AuthID)
		assert.Equal(t, authProvider1, userInfo.AuthProvider)
		assert.Equal(t, extras1["salt"], userInfo.AuthExtras["salt"])
		assert.Equal(t, extras1["verifier"], userInfo.AuthExtras["verifier"])
		assert.Equal(t, "inactive", userInfo.State)
	})

	t.Run("GetUserNotFound", func(t *testing.T) {
		ctx, _, repo := newTestRepo(t)

		_, err := repo.GetUserInfoByAuthID(ctx, "nonexistent@example.com")
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})

	t.Run("CheckIfUserExists", func(t *testing.T) {
		ctx, _, repo := newTestRepo(t)

		// Check before creation
		exists, err := repo.CheckIfUserExists(ctx, AuthID1)
		require.NoError(t, err)
		assert.False(t, exists, "User should not exist before creation")

		// Create user
		err = repo.CreateUser(ctx, AuthID1, displayName1, authProvider1, extras1)
		require.NoError(t, err)

		// Check after creation
		exists, err = repo.CheckIfUserExists(ctx, AuthID1)
		require.NoError(t, err)
		assert.True(t, exists, "User should exist after creation")

		// Check for a different, non-existent user
		exists, err = repo.CheckIfUserExists(ctx, "otheruser@example.com")
		require.NoError(t, err)
		assert.False(t, exists, "Non-existent user should not be found")
	})

	t.Run("ActivateUser", func(t *testing.T) {
		ctx, _, repo := newTestRepo(t)

		// Create an inactive user
		err := repo.CreateUser(ctx, AuthID1, displayName1, authProvider1, extras1)
		require.NoError(t, err)

		userInfo, err := repo.GetUserInfoByAuthID(ctx, AuthID1)
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.Equal(t, "inactive", userInfo.State, "User should be inactive initially")

		// Activate the user
		err = repo.ActivateUser(ctx, userInfo.ID)
		require.NoError(t, err)

		// Verify user is active
		userInfo, err = repo.GetUserInfoByAuthID(ctx, AuthID1)
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.Equal(t, "active", userInfo.State, "User should be active after activation")

		// Attempt to activate a non-existent user
		// Current implementation of ActivateUser does not return an error if user is not found.
		err = repo.ActivateUser(ctx, 9999)
		require.Error(t, err, "user not found")

		// Attempt to activate an already active user
		err = repo.ActivateUser(ctx, userInfo.ID) // User is already active
		require.NoError(t, err)
		userInfo, err = repo.GetUserInfoByAuthID(ctx, AuthID1)
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.Equal(t, "active", userInfo.State, "User should remain active")
	})

	t.Run("CreateUserWithUnmarshallableExtras", func(t *testing.T) {
		ctx, client, repo := newTestRepo(t)

		unmarshallableExtras := make(chan int) // Channels cannot be marshalled to JSON
		err := repo.CreateUser(ctx, AuthID2, displayName2, authProvider1, unmarshallableExtras)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal user extras")

		// Verify User entity was created (as User creation precedes marshalling extras)
		createdUser, userErr := client.User.Query().Where(user.DisplayNameEQ(displayName2)).Only(ctx)
		require.NoError(t, userErr, "Querying for the created user should not fail")
		require.NotNil(t, createdUser, "User entity should have been created")
		assert.Equal(t, "inactive", createdUser.State)

		// Verify UserAuth was not created
		exists, _ := repo.CheckIfUserExists(ctx, AuthID2)
		assert.False(t, exists, "UserAuth should not exist if marshalling extras failed")
	})

	t.Run("GetUserInfoWithMalformedAuthExtras", func(t *testing.T) {
		ctx, client, repo := newTestRepo(t)

		// Create a user normally
		err := repo.CreateUser(ctx, AuthID1, displayName1, authProvider1, extras1)
		require.NoError(t, err)

		// Manually update UserAuth with invalid JSON for AuthExtras
		ua, err := client.UserAuth.Query().Where(ent_userauth.AuthIDEQ(AuthID1)).Only(ctx)
		require.NoError(t, err)
		_, err = client.UserAuth.UpdateOne(ua).SetAuthExtras("this-is-not-json").Save(ctx)
		require.NoError(t, err)

		// Attempt to get user info
		_, err = repo.GetUserInfoByAuthID(ctx, AuthID1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal user extras")
	})
}
