package locker

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"Locker/internal/fileutil"

	"golang.org/x/crypto/argon2"
)

const (
	LockMode                = "lock"
	UnlockMode              = "unlock"
	IdentifierExtension     = ".locked"
	saltSize                = 32
	defaultGarbageBytesSize = 50 * 1024 * 1024
	chunkForBigFileSize     = defaultGarbageBytesSize
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

func encryptFileName(gcm cipher.AEAD, filePath string) (encryptedFileName []byte, lengthInBytes []byte) {
	fileName := filepath.Base(filePath)
	encryptedFileName = encrypt(gcm, []byte(fileName))

	lengthInBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(lengthInBytes, uint64(len(encryptedFileName)))

	return encryptedFileName, lengthInBytes
}

func encryptSmallFile(gcm cipher.AEAD, salt []byte, originalFilePath string) string {
	encryptedFileName, encryptedFileNameLength := encryptFileName(gcm, originalFilePath)

	originalData, _ := os.ReadFile(originalFilePath)
	encryptedData := encrypt(gcm, originalData)

	// naming encrypted file with salt to prevent
	// accidentally change the file name if encrypted file name is placed as file name which will fail decryption
	// reach over 255 chars limit when naming file
	// now the file name doesnt effect at all even if one char is changed or renamed completely
	newFileName := hex.EncodeToString(salt) + IdentifierExtension
	newFilePath := fileutil.GetPathToFile(originalFilePath) + newFileName
	file, _ := os.OpenFile(newFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.Write(salt)
	writer.Write(encryptedFileNameLength)
	writer.Write(encryptedFileName)
	writer.Write(encryptedData)

	return newFileName
}

func encryptBigFile(gcm cipher.AEAD, salt []byte, originalFilePath string) string {
	newFileName := hex.EncodeToString(salt) + IdentifierExtension
	newFilePath := fileutil.GetPathToFile(originalFilePath) + newFileName

	encryptedFile, _ := os.OpenFile(newFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer encryptedFile.Close()
	writer := bufio.NewWriter(encryptedFile)
	defer writer.Flush()

	encryptedFileName, encryptedFileNameLength := encryptFileName(gcm, originalFilePath)
	writer.Write(salt)
	writer.Write(encryptedFileNameLength)
	writer.Write(encryptedFileName)

	originalFile, _ := os.Open(originalFilePath)
	defer originalFile.Close()
	reader := bufio.NewReader(originalFile)

	chunk := make([]byte, chunkForBigFileSize)
	for {
		n, err := reader.Read(chunk)
		if err == io.EOF {
			break
		}

		encryptedChunk := encrypt(gcm, chunk[:n])
		writer.Write(encryptedChunk)
	}

	return newFileName
}

func overWriteWithGarbage(originalFilePath string, passes int) {
	randomBytes := make([]byte, defaultGarbageBytesSize)
	fileInfo, _ := os.Stat(originalFilePath)
	fileSize := int(fileInfo.Size())

	var writtenPasses int
	for writtenPasses != passes {
		file, _ := os.OpenFile(originalFilePath, os.O_TRUNC|os.O_WRONLY, 0o000)
		defer file.Close()
		writer := bufio.NewWriter(file)
		defer writer.Flush()

		var writtenBytes int
		for {
			if writtenBytes+defaultGarbageBytesSize >= fileSize {
				lastRandomBytes := make([]byte, fileSize-writtenBytes)
				rand.Read(lastRandomBytes)
				writer.Write(lastRandomBytes)
				break
			}
			rand.Read(randomBytes)
			n, _ := writer.Write(randomBytes)
			writtenBytes = writtenBytes + n
		}
		writtenPasses += 1
	}
}

func Lock(passphrase, filePath string, overWriteWithGarbagePasses int) (encryptedFile string) {
	salt := make([]byte, saltSize)
	rand.Read(salt)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	if fileutil.IsSmallFile(filePath, false) {
		encryptedFile = encryptSmallFile(gcm, salt, filePath)
	} else {
		encryptedFile = encryptBigFile(gcm, salt, filePath)
	}
	overWriteWithGarbage(filePath, overWriteWithGarbagePasses)
	os.Remove(filePath)

	return encryptedFile
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

func decryptFileName(gcm cipher.AEAD, encryptedFilePath string) (string, error) {
	dirpathToFile, encryptedFileName := filepath.Split(encryptedFilePath)
	removedIdentifierFileName, _ := strings.CutSuffix(encryptedFileName, IdentifierExtension)

	decodedFileName, err := base64.RawURLEncoding.DecodeString(removedIdentifierFileName)
	if err != nil {
		return "", err
	}

	originalFileName, err := decrypt(gcm, decodedFileName[:gcm.NonceSize()], decodedFileName[gcm.NonceSize():])
	if err != nil {
		return "", err
	}

	return dirpathToFile + string(originalFileName), nil
}

func decryptSmallFile(gcm cipher.AEAD, encryptedFilePath, originalFilePath string) {
	encryptedFileContent, _ := os.ReadFile(encryptedFilePath)

	nonce := encryptedFileContent[saltSize : saltSize+gcm.NonceSize()]
	encryptedData := encryptedFileContent[saltSize+gcm.NonceSize():]
	// ignore err cause if decryptFileName get the job done which means the key is valid
	originalFileContent, _ := decrypt(gcm, nonce, encryptedData)

	os.WriteFile(originalFilePath, originalFileContent, 0o644)
}

func decryptBigFile(gcm cipher.AEAD, encryptedFilePath, originalFilePath string) {
	encryptedFile, _ := os.Open(encryptedFilePath)
	encryptedFile.Seek(saltSize, io.SeekStart) // skip salt
	defer encryptedFile.Close()
	reader := bufio.NewReader(encryptedFile)

	originalFile, _ := os.OpenFile(originalFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer originalFile.Close()
	writer := bufio.NewWriter(originalFile)
	defer writer.Flush()

	// the encrypted chunk is nonce+encryptedData+tag (12bytes + 50MB + 28bytes)
	encryptedChunkSize := gcm.NonceSize() + chunkForBigFileSize + gcm.Overhead()
	encryptedChunk := make([]byte, encryptedChunkSize)
	for {
		n, err := reader.Read(encryptedChunk)
		if err == io.EOF {
			break
		}

		originalChunk, _ := decrypt(gcm, encryptedChunk[:gcm.NonceSize()], encryptedChunk[gcm.NonceSize():n])
		writer.Write(originalChunk)
	}
}

func Unlock(passphrase, encryptedFilePath string) string {
	salt := getSaltFromEncryptedFile(encryptedFilePath)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	originalFilePath, err := decryptFileName(gcm, encryptedFilePath)
	if err != nil {
		return "[-] Invalid Passphrase"
	}

	if fileutil.IsSmallFile(encryptedFilePath, true) {
		decryptSmallFile(gcm, encryptedFilePath, originalFilePath)
	} else {
		decryptBigFile(gcm, encryptedFilePath, originalFilePath)
	}
	os.Remove(encryptedFilePath)

	return "[+] Unlocked   " + originalFilePath
}
