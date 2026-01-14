package main

import (
	"bufio"
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

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("passphrase: ")
	passphrase, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	if os.Args[1] == lockMode {
		result := locker.Lock(passphrase, filePath)
		fmt.Println(result)
	} else if os.Args[1] == unlockMode {
		result := locker.Unlock(passphrase, filePath)
		fmt.Println(result)
	}
}
