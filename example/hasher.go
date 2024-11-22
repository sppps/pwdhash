package main

import (
	"os"
	"syscall"

	"github.com/sppps/pwdhash"
	"golang.org/x/term"
)

func main() {

	print("Enter Password: ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	if len(os.Args) > 1 {
		err = pwdhash.Validate(string(bytePassword), os.Args[1])
		if err != nil {
			panic(err)
		}
		println("Password is valid")
	} else {
		hash, err := pwdhash.Hash(string(bytePassword))
		if err != nil {
			panic(err)
		}
		println(pwdhash.GetConfig().String())
		println("Password hash:", hash)
	}
}
