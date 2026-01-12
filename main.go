package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

func driveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

func encryptFile(key []byte, filePath string) ([]byte, error) {
	originalData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nil, nonce, originalData, nil)

	return append(nonce, ciphertext...), nil
}

func decryptFile(key []byte, filePath string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := encryptedData[16 : 16+gcm.NonceSize()]
	ciphertext := encryptedData[16+gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func getSaltFromEncryptedFile(encryptedFile string) ([]byte, error) {
	salt := make([]byte, 16)

	file, err := os.Open(encryptedFile)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	file.Read(salt)
	return salt, nil
}

func main() {
	filePath := os.Args[2]

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	if os.Args[1] == "lock" {
		salt := make([]byte, 16)
		rand.Read(salt)
		key := driveKey([]byte(password), salt)

		encryptedData, err := encryptFile(key, filePath)
		if err != nil {
			fmt.Println(err)
			return
		}

		dataToWrite := append(salt, encryptedData...)
		os.WriteFile(filePath, dataToWrite, 0o644)

	} else if os.Args[1] == "unlock" {
		salt, err := getSaltFromEncryptedFile(filePath)
		if err != nil {
			fmt.Println(err)
			return
		}

		key := driveKey([]byte(password), salt)
		originalData, err := decryptFile(key, filePath)
		if err != nil {
			fmt.Println(err)
			return
		}

		os.WriteFile(filePath, originalData, 0o644)
	}
}
