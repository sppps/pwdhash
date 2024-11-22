package pwdhash

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// encodeArgon2Hash encodes the Argon2 hash with the salt and configuration settings into a string.
func encodeArgon2Hash(salt, hash []byte, config Config) string {
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		config.Memory,
		config.Time,
		config.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// validateArgon2 validates a password against an Argon2 hash.
func validateArgon2(password, encodedHash string) error {
	// parsing encoded hash
	parts := strings.Split(encodedHash, "$")

	if len(parts) != 6 || parts[1] != "argon2id" {
		return fmt.Errorf("invalid Argon2 hash format")
	}

	if parts[2] != "v=19" {
		return fmt.Errorf("invalid Argon2 version")
	}

	// extracting hash parameters
	params := strings.Split(parts[3], ",")
	var time uint32
	var memory uint32
	var threads uint8
	for _, param := range params {
		key, value, found := strings.Cut(param, "=")
		if !found {
			return fmt.Errorf("invalid Argon2 hash format")
		}
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid Argon2 hash format")
		}
		switch key {
		case "m":
			memory = uint32(val)
		case "t":
			time = uint32(val)
		case "p":
			threads = uint8(val)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %v", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("failed to decode hash: %v", err)
	}

	// generating new hash to compare
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))

	if !bytes.Equal(computedHash, hash) {
		return fmt.Errorf("validation failed")
	}

	return nil
}

func hashArgon2id(password string) (string, error) {
	salt, err := generateRandomSalt(16)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, currentConfig.Time, currentConfig.Memory, currentConfig.Threads, 32)
	return encodeArgon2Hash(salt, hash, currentConfig), nil
}
