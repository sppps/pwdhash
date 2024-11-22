package pwdhash

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func hashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), currentConfig.Cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password using bcrypt: %v", err)
	}
	return string(hash), err
}

func validateBcrypt(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
