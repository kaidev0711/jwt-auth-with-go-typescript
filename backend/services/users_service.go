package services

import (
	"github.com/kaidev0711/jwt-auth-with-go-typescript/backend/domain/users"
	"github.com/kaidev0711/jwt-auth-with-go-typescript/backend/utils/errors"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(user users.User) (*users.User, *errors.RestErr) {
	if err := user.Validate(); err != nil {
		return nil, err
	}
	// encrypt password
	pwSlice, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		return nil, errors.NewBadRequestError("Failed encrypt password")
	}
	user.Password = string(pwSlice[:])
	if err := user.Save(); err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUser(user users.User) (*users.User, *errors.RestErr) {
	result := &users.User{Email: user.Email}
	if err := result.GetByEmail(); err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)); err != nil {
		return nil, errors.NewBadRequestError("Failded to decrypt password")
	}
	resultPw := &users.User{ID: result.ID, FirstName: result.FirstName, LastName: result.LastName, Email: result.Email}
	return resultPw, nil
}
