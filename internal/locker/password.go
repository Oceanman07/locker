package locker

import (
	"fmt"

	"golang.org/x/term"
)

func GetPassphrase() string {
	fmt.Print("passphrase:")
	passphrase, _ := term.ReadPassword(0)
	return string(passphrase)
}
