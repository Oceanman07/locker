package main

import (
	"bufio"
	"fmt"
	"os"

	"Locker/internal/locker"
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

	if os.Args[1] == "lock" {
		encryptedFilePath := locker.Lock(passphrase, filePath)
		fmt.Println("[+] Locked   ", encryptedFilePath)
	} else if os.Args[1] == "unlock" {
	}
}
