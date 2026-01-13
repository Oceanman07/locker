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

func encryptSmallFile(gcm cipher.AEAD, salt []byte, originalFilePath, encryptedFilePath string) {
	originalData, _ := os.ReadFile(originalFilePath)
	encryptedData := encrypt(gcm, originalData)
	dataToWrite := append(salt, encryptedData...)
	os.WriteFile(encryptedFilePath, dataToWrite, 0o644)
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
	encryptSmallFile(gcm, salt, filePath, encryptedFilePath)
	overWriteGarbageAndDelete(filePath)

	return encryptedFilePath
}

func getSaltFromEncryptedFile(encryptedFilePath string) []byte {
	salt := make([]byte, saltSize)

	file, _ := os.Open(encryptedFilePath)
	defer file.Close()

	file.Read(salt)
	return salt
}

func decrypt(gcm cipher.AEAD, nonce, encryptedData []byte) ([]byte, error) {
	originalData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return originalData, nil
}

func DecryptFile(passphrase, filePath string) {
}
