package main

import (
	"fmt"

	"Locker/internal/fileutil"
	"Locker/internal/locker"
	"Locker/internal/parser"
)

const (
	lockMode   = "lock"
	unlockMode = "unlock"
)

func main() {
	args, err := parser.ParseArgs()
	if err != nil {
		fmt.Println(err)
		return
	}

	if !fileutil.IsExist(args.Path) {
		fmt.Println("[-] Path not found")
		return
	}

	fmt.Print("passphrase:")
	passphrase := locker.GetPassphrase()
	fmt.Println()

	if args.Mode == lockMode {
		if !args.LockArgs.SkipValidatePassphrase {
			if !locker.IsValidPassphrase(passphrase) {
				fmt.Println("[-] Passphrase must contain at least lowercase, uppercase and 1 number")
				return
			}
		}

		// reconfirm passphrase
		fmt.Print("confirm: ")
		confirmPassphrase := locker.GetPassphrase()
		if confirmPassphrase != passphrase {
			fmt.Println("[-] Passphrases didn't match")
			return
		}
		fmt.Println()

		result := locker.Lock(passphrase, args.Path)
		fmt.Println(result)

	} else if args.Mode == unlockMode {
		result := locker.Unlock(passphrase, args.Path)
		fmt.Println(result)
	}
}
