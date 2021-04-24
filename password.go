package main

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func getPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pwd, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}
	return pwd, nil
}
