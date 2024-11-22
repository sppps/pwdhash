package pwdhash

import "crypto/rand"

// generateRandomSalt generates a random salt of the given size.
func generateRandomSalt(size int) ([]byte, error) {
	r := currentConfig.RandSrc
	if r == nil {
		r = rand.Reader
	}
	salt := make([]byte, size)
	_, err := r.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
