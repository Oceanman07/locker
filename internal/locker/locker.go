package locker

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	identifierExtension     = ".locked"
	saltSize                = 16
	defaultGarbageBytesSize = 100 * 1024 * 1024
)

func driveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
}

func encrypt(gcm cipher.AEAD, data []byte) []byte {
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...)
}

func encryptFileName(gcm cipher.AEAD, filePath string) string {
	dirpathToFile, fileName := filepath.Split(filePath)
	encryptedFileName := encrypt(gcm, []byte(fileName))
	return dirpathToFile + base64.RawURLEncoding.EncodeToString(encryptedFileName) + identifierExtension
}

func encryptSmallFile(gcm cipher.AEAD, originalFilePath, encryptedFilePath string) {
	originalData, _ := os.ReadFile(originalFilePath)
	encryptedData := encrypt(gcm, originalData)
	os.WriteFile(encryptedFilePath, encryptedData, 0o644)
}

func overWriteGarbageAndDelete(originalFilePath string) {
	file, _ := os.OpenFile(originalFilePath, os.O_TRUNC|os.O_WRONLY, 0o000)
	defer file.Close()
	writer := bufio.NewWriter(file)

	randomBytes := make([]byte, defaultGarbageBytesSize)
	fileInfo, _ := os.Stat(originalFilePath)
	fileSize := int(fileInfo.Size())

	var writtenBytes int
	for {
		if writtenBytes+defaultGarbageBytesSize >= fileSize {
			randomBytes = make([]byte, fileSize-writtenBytes)
			rand.Read(randomBytes)
			writer.Write(randomBytes)
			break
		}
		rand.Read(randomBytes)
		n, _ := writer.Write(randomBytes)
		writtenBytes = writtenBytes + n
	}

	os.Remove(originalFilePath)
}

func Lock(passphrase, filePath string) string {
	salt := make([]byte, saltSize)
	rand.Read(salt)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	encryptedFilePath := encryptFileName(gcm, filePath)
	encryptSmallFile(gcm, filePath, encryptedFilePath)
	overWriteGarbageAndDelete(filePath)

	return encryptedFilePath
}

func DecryptFile(key []byte, filePath string) ([]byte, error) {
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

func GetSaltFromEncryptedFile(encryptedFile string) ([]byte, error) {
	salt := make([]byte, 16)

	file, err := os.Open(encryptedFile)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	file.Read(salt)
	return salt, nil
}
