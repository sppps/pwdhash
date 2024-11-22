package pwdhash

import (
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// stores configuration parameters for password hashing.
type Config struct {
	Algorithm Algorithm // hashing algorithm (Argon2, Bcrypt)
	Memory    uint32    // Argon2 memory
	Time      uint32    // Argon2 timer
	Threads   uint8     // Argon2 parallelism
	Cost      int       // Bcrypt cost
	RandSrc   io.Reader // random number generator
}

// defines the supported hashing algorithms.
type Algorithm int

const (
	Argon2id Algorithm = iota
	Bcrypt
)

// provides the default configuration for hashing
var DefaultConfig = Config{
	Algorithm: Argon2id,           // use Argon2id for default
	Memory:    64 * 1024,          // 64 Mbytes
	Time:      3,                  // 3 iterations
	Threads:   4,                  // 4 threads
	Cost:      bcrypt.DefaultCost, // default cost
}

// provides the paranoid configuration for hashing.
var ParanoidConfig = Config{
	Algorithm: Argon2id,       // use Argon2id for default
	Memory:    192 * 1024,     // 64 Mbytes
	Time:      12,             // 3 iterations
	Threads:   8,              // 4 threads
	Cost:      bcrypt.MaxCost, // maximum cost
}

var currentConfig = DefaultConfig

// sets the global configuration for password hashing
func SetConfig(cfg Config) {
	currentConfig = cfg
}

// returns the current hashing configuration
func GetConfig() Config {
	return currentConfig
}

func (c Config) String() (s string) {
	switch currentConfig.Algorithm {
	case Argon2id:
		return fmt.Sprintf("Argon2id (m=%d, t=%d, p=%d)", currentConfig.Memory, currentConfig.Time, currentConfig.Threads)
	case Bcrypt:
		return fmt.Sprintf("Bcrypt (cost=%d)", currentConfig.Cost)
	default:
		return "unknown algorithm"
	}
}
