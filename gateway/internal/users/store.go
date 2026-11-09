// Package users reads the identity fields the gateway needs from MySQL.
package users

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

const SystemAdminRole = "system-admin"

var ErrNotFound = errors.New("user not found")

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Name         string
	Role         string
	IsActive     bool
}

type Store interface {
	ByID(ctx context.Context, id int64) (User, error)
	ByEmail(ctx context.Context, email string) (User, error)
}

type GormStore struct {
	DB *gorm.DB
}

func (s GormStore) ByID(ctx context.Context, id int64) (User, error) {
	return s.first(ctx, "id = ?", id)
}

func (s GormStore) ByEmail(ctx context.Context, email string) (User, error) {
	return s.first(ctx, "email = ?", email)
}

func (s GormStore) first(ctx context.Context, query string, arg any) (User, error) {
	var user User
	err := s.DB.WithContext(ctx).Where(query, arg).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return User{}, ErrNotFound
	}
	return user, err
}
