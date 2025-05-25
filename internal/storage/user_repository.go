package storage

import "fmt"

type User interface {
	GetUsername() string
	GetPassword() string
	IsValidUser(string, string) bool
}

type StorageUser struct {
	Username string
	Password string
}

func (u *StorageUser) IsValidUser(username, password string) bool {
	return u.Username == username && u.Password == password
}

func (u *StorageUser) GetUsername() string {
	return u.Username
}

func (u *StorageUser) GetPassword() string {
	return u.Password
}

type UserRepo interface {
	Create(user User) error
	FindByUsername(username string) (User, error)
	DeleteByUsername(username string) error
}

type UserRepoImpl struct {
	Users map[string]User
}

// Create implements UserRepo.
func (u *UserRepoImpl) Create(user User) error {
	u.Users[user.GetUsername()] = user
	return nil
}

// DeleteByUsername implements UserRepo.
func (u *UserRepoImpl) DeleteByUsername(username string) error {
	if _, ok := u.Users[username]; !ok {
		return fmt.Errorf("user not found")
	}
	delete(u.Users, username)
	return nil
}

// FindByUsername implements UserRepo.
func (u *UserRepoImpl) FindByUsername(username string) (User, error) {
	user, ok := u.Users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func NewUserRepo() UserRepo {
	return &UserRepoImpl{
		Users: make(map[string]User),
	}
}
