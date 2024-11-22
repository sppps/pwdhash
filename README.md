# pwdhash 🔐

[pwdhash](github.com/sppps/pwdhash) is a lightweight, easy-to-use library for secure password hashing and validation in Go. It leverages industry-standard algorithms to ensure your application stays safe without unnecessary complexity.

## Features 🚀

- 🔒 **Secure hashing** with Argon2 (default) or Bcrypt.
- 🔑 **Easy validation** of hashed passwords.
- ⚡ **Configurable parameters** for performance tuning.
- ✅ Designed for simplicity and readability.

## Installation 📦

Install the library using `go get`:

```bash
go get github.com/sppps/pwdhash
```

## Quick Start 🌟

### 1. Hashing a password

```go
package main

import (
    "fmt"
    "github.com/sppps/pwdhash"
)

func main() {
    password := "MySecureP@ssw0rd"

    // Hash the password
    hash, err := pwdhash.Hash(password)
    if err != nil {
        panic(err)
    }

    fmt.Println("Hashed password:", hash)
}
```

### 2. Validating a password

```go
package main

import (
    "fmt"
    "github.com/sppps/pwdhash"
)

func main() {
    hash := "$argon2id$v=19$m=65536,t=3,p=2$..." // Example hash
    password := "MySecureP@ssw0rd"

    // Validate the password
    match := hash.Validate(password, hash)
    if match == nil {
        fmt.Println("Password is valid!")
    } else {
        fmt.Println("Invalid password!")
    }
}
```

## Configuration ⚙️

You can customize the hashing algorithm and parameters:

```go
gopassword.SetConfig(gopassword.Config{
    Algorithm: gopassword.Argon2id, // or gopassword.Bcrypt
    Memory:    65536,              // Argon2-specific
    Time:      3,
    Threads:   2,
})
```

## Why Use pwdhash? 🤔

- **Security**: Follows best practices for password hashing.
- **Simplicity**: Easy-to-read API for developers of all levels.
- **Flexibility**: Configurable for various application needs. 

## Roadmap 🛣️

- [ ] Add support for Scrypt.
- [ ] Benchmark performance against other libraries.
- [ ] Implement automatic upgrades for old password hashes.

## Contributing 🤝

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-name).
3. Commit your changes (git commit -m "Add feature").
4. Push to the branch (git push origin feature-name).
5. Create a pull request.

## License 📄

his project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

Inspired by the simplicity of bcrypt and argon2.
Thanks to the Go community for their amazing tools and libraries.

## Contact ✉️

Feel free to reach out with feedback, questions, or suggestions!

[GitHub](https://github.com/sppps)
[Email](mailto:sergey@gogin.pro)
