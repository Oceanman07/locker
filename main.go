package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

func driveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

func main() {
	password := []byte("SuperPassword")
	salt := make([]byte, 16)
	rand.Read(salt)

	key := driveKey(password, salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("This is a text")
	cipherdata := gcm.Seal(nil, nonce, plaintext, nil)

	fmt.Println(len(cipherdata))
	fmt.Println(cipherdata)
	fmt.Println(string(cipherdata))

	fmt.Println()

	originalPlaintext, err := gcm.Open(nil, nonce, cipherdata, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(originalPlaintext)
	fmt.Println(string(originalPlaintext))
}
