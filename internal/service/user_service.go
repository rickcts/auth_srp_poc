package service

import (
	"context"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
)

var _ UserGenerator = (*userService)(nil)

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) *userService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) UpdateUserInfo(ctx context.Context, authID, displayName string) error {
	return s.userRepo.UpdateUserInfoByAuthID(ctx, authID, displayName)
}

func (s *userService) DeleteUser(ctx context.Context, authID string) error {
	return s.userRepo.DeleteUser(ctx, authID)
}
