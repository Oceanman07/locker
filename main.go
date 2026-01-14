package main

import (
	"fmt"
	"os"

	"Locker/internal/locker"
)

const (
	lockMode   = "lock"
	unlockMode = "unlock"
)

func main() {
	filePath := os.Args[2]

	passphrase := locker.GetPassphrase()
	fmt.Println()

	if os.Args[1] == lockMode {
		fmt.Print("Confirm ")
		confirmPassphrase := locker.GetPassphrase()
		if confirmPassphrase != passphrase {
			fmt.Println("[-] Passphrases didn't match")
			return
		}
		fmt.Println()

		result := locker.Lock(passphrase, filePath)
		fmt.Println(result)

	} else if os.Args[1] == unlockMode {
		result := locker.Unlock(passphrase, filePath)
		fmt.Println(result)
	}
}
