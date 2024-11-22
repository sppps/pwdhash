package pwdhash_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sppps/pwdhash"
)

func TestDefaultPwdhash(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password with Argon2id",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "Valid password with special chars",
			password: "P@ssw0rd!#",
			wantErr:  false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := pwdhash.Hash(tt.password)

			if !strings.HasPrefix(hash, "$argon2id$") {
				t.Errorf("invalid Argon2id prefix")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && hash == "" {
				t.Errorf("Hash() = %v, want non-empty hash", hash)
			}

			err = pwdhash.Validate(tt.password, hash)

			if err != nil {
				t.Errorf("Hash() = %v, want non-empty hash", hash)
			}
		})
	}
}

func TestBcrypt(t *testing.T) {
	pwdhash.SetConfig(pwdhash.Config{
		Algorithm: pwdhash.Bcrypt,
	})

	hash, _ := pwdhash.Hash("P@ssw0rd!#")

	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("invalid Bcrypt prefix")
	}

	err := pwdhash.Validate("P@ssw0rd!#", hash)

	if err != nil {
		t.Errorf("Hash() = %v, want non-empty hash", hash)
	}

	_, err = pwdhash.Hash("password, longer that 72 bytes, which is the longest password bcrypt will operate on")

	if err == nil {
		t.Errorf("err must not be nil")
	}
}

func TestGetSetConfig(t *testing.T) {

	pwdhash.SetConfig(pwdhash.DefaultConfig)

	if pwdhash.GetConfig().String() != "Argon2id (m=65536, t=3, p=4)" {
		t.Errorf("wrong config string: %s", pwdhash.GetConfig().String())
	}

	cfg := pwdhash.Config{
		Algorithm: pwdhash.Bcrypt,
		Cost:      128,
	}

	pwdhash.SetConfig(cfg)

	currCfg := pwdhash.GetConfig()

	if cfg != currCfg {
		t.Errorf("wrong config")
	}

	if cfg.String() != "Bcrypt (cost=128)" {
		t.Errorf("wrong config string")
	}

	pwdhash.SetConfig(pwdhash.Config{
		Algorithm: 1024,
	})

	if cfg.String() != "unknown algorithm" {
		t.Errorf("wrong config string")
	}

	_, err := pwdhash.Hash("P@ssw0rd!#")

	if err == nil {
		t.Errorf("err must not be nil")
	}
}

type faultyReader struct {
}

func (r faultyReader) Read([]byte) (n int, err error) {
	return 0, errors.New("random generator error")
}

func TestRandSourceFault(t *testing.T) {
	pwdhash.SetConfig(pwdhash.Config{
		Algorithm: pwdhash.Argon2id,
		RandSrc:   faultyReader{},
	})

	_, err := pwdhash.Hash("P@ssw0rd!#")

	if err == nil {
		t.Errorf("err must not be nil")
	}
}

func TestArgon2Errors(t *testing.T) {
	pwdhash.SetConfig(pwdhash.DefaultConfig)

	err := pwdhash.Validate("P@ssw0rd!#", "not valid argon hash")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$oops!")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=20$$$")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=19$mx,tz,pq$$")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=19$m=x,t=z,p=q$$")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=19$m=1024,t=1,p=1$wrong!zalt$")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=19$m=1024,t=1,p=1$ABCD$wrong!hash")

	if err == nil {
		t.Errorf("err must not be nil")
	}

	err = pwdhash.Validate("P@ssw0rd!#", "$argon2id$v=19$m=1024,t=1,p=1$ABCD$EFGH")

	if err == nil {
		t.Errorf("err must not be nil")
	}
}
