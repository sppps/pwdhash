package pwdhash

import (
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// Config хранит параметры конфигурации для хеширования паролей.
type Config struct {
	Algorithm Algorithm // Алгоритм хеширования (Argon2, Bcrypt)
	Memory    uint32    // Память для Argon2
	Time      uint32    // Время для Argon2
	Threads   uint8     // Количество потоков для Argon2
	Cost      int       // Стоимость (сложность) для Bcrypt
	LogWriter io.Writer
	RandSrc   io.Reader
}

// Algorithm определяет поддерживаемые алгоритмы хеширования.
type Algorithm int

const (
	Argon2id Algorithm = iota
	Bcrypt
)

// DefaultConfig предоставляет конфигурацию по умолчанию для хеширования.
var DefaultConfig = Config{
	Algorithm: Argon2id,           // По умолчанию используем Argon2id
	Memory:    64 * 1024,          // 64 MB для Argon2
	Time:      3,                  // 3 итерации для Argon2
	Threads:   4,                  // 2 потока для Argon2
	Cost:      bcrypt.DefaultCost, // Стоимость по умолчанию для Bcrypt
}

var ParanoidConfig = Config{
	Algorithm: Argon2id,
	Memory:    192 * 1024,
	Time:      12,
	Threads:   8,
	Cost:      bcrypt.MaxCost,
}

var currentConfig = DefaultConfig

// SetConfig устанавливает глобальную конфигурацию для хеширования паролей.
func SetConfig(cfg Config) {
	currentConfig = cfg
}

// GetConfig возвращает текущую конфигурацию хеширования.
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
