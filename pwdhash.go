package pwdhash

import (
	"errors"
	"strings"
)

// Hash generates a secure hash for the given password.
func Hash(password string) (string, error) {
	switch currentConfig.Algorithm {
	case Argon2id:
		return hashArgon2id(password)
	case Bcrypt:
		return hashBcrypt(password)
	default:
		return "", errors.New("unsupported hashing algorithm")
	}
}

// Validate checks if the provided password matches the hashed password.
func Validate(password, hash string) error {
	if strings.HasPrefix(hash, "$argon2id$") {
		return validateArgon2(password, hash)
	} else if strings.HasPrefix(hash, "$2") {
		return validateBcrypt(password, hash)
	}
	return errors.New("unsupported hash format")
}
