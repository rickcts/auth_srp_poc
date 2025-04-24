package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/rickcts/srp/internal/models"
	"github.com/rickcts/srp/internal/repository"
)

// MemoryUserRepository implements UserRepository in memory (NOT FOR PRODUCTION)
type MemoryUserRepository struct {
	users map[string]*models.User
	mutex sync.RWMutex
}

func NewMemoryUserRepository() repository.UserRepository {
	return &MemoryUserRepository{
		users: make(map[string]*models.User),
	}
}

func (r *MemoryUserRepository) CreateUserCreds(ctx context.Context, username, saltHex, verifierHex string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.users[username]; exists {
		return repository.ErrUserExists
	}

	r.users[username] = &models.User{
		Username: username,
		Salt:     saltHex,
		Verifier: verifierHex,
	}
	fmt.Printf("User registered: %s\n", username) // Debug log
	return nil
}

func (r *MemoryUserRepository) GetUserCredsByUsername(ctx context.Context, username string) (string, string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[username]
	if !exists {
		return "", "", repository.ErrUserNotFound
	}
	return user.Salt, user.Verifier, nil
}
