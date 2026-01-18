package locker

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"Locker/internal/fileutil"

	"golang.org/x/crypto/argon2"
)

const (
	LockMode                = "lock"
	UnlockMode              = "unlock"
	IdentifierExtension     = ".locked"
	saltSize                = 32
	gcmNoneSize             = 12
	defaultGarbageBytesSize = 50 * 1024 * 1024
	chunkForNormalFile      = defaultGarbageBytesSize
	// the encrypted chunk is nonce+encryptedData+tag (12bytes + 50MB + 16bytes)
	chunkForEncryptedFile = 12 + chunkForNormalFile + 16
)

func convertBytes(size float64) string {
	units := []string{"bytes", "KB", "MB", "GB"}
	for _, u := range units {
		if size < 1024 {
			return strconv.FormatFloat(size, 'f', 2, 64) + " " + u
		}
		size = size / 1024
	}
	return ""
}

func logMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Printf(
		"+ Alloc=%s | Sys=%s | NumGC=%d\n",
		convertBytes(float64(m.Alloc)), convertBytes(float64(m.Sys)), m.NumGC)
}

func driveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
}

func getNonceForGCM() []byte {
	nonce := make([]byte, gcmNoneSize)
	rand.Read(nonce)
	return nonce
}

func encryptFileName(gcm cipher.AEAD, filePath string) (encryptedFileName []byte, lengthInBytes []byte) {
	fileName := filepath.Base(filePath)

	nonce := getNonceForGCM()
	ciphertext := gcm.Seal(nil, nonce, []byte(fileName), nil)
	encryptedFileName = append(nonce, ciphertext...)

	lengthInBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(lengthInBytes, uint64(len(encryptedFileName)))

	return encryptedFileName, lengthInBytes
}

func encryptFile(gcm cipher.AEAD, salt []byte, originalFilePath string) string {
	// naming encrypted file with salt to prevent
	// accidentally change the file name if encrypted file name is placed as file name which will fail decryption
	// reach over 255 chars limit when naming file
	// now the file name doesnt effect at all even if one char is changed or renamed completely
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

	preallocateBufferForDst := make([]byte, 0, chunkForNormalFile+gcm.Overhead())

	chunk := make([]byte, chunkForNormalFile)
	for {
		n, err := reader.Read(chunk)
		if err == io.EOF {
			break
		}

		nonce := getNonceForGCM()
		encryptedChunk := gcm.Seal(preallocateBufferForDst, nonce, chunk[:n], nil)

		writer.Write(nonce)
		writer.Write(encryptedChunk)

		logMemory()
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

			logMemory()
		}
		writtenPasses += 1
	}
}

func Lock(passphrase, filePath string, overWriteWithGarbagePasses int) string {
	salt := make([]byte, saltSize)
	rand.Read(salt)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	encryptedFile := encryptFile(gcm, salt, filePath)
	fmt.Println("==========================OverWriteWithGarbage=============================")
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
	reader, _ := os.Open(encryptedFilePath)
	defer reader.Close()

	// skip salt
	reader.Seek(saltSize, io.SeekStart)

	// get lengthInBytes of encryptedFileName
	lengthInBytes := make([]byte, 8)
	reader.Read(lengthInBytes)
	intLength := binary.BigEndian.Uint64(lengthInBytes)

	encryptedFileName := make([]byte, intLength)
	reader.Read(encryptedFileName)

	originalFileName, err := decrypt(gcm, encryptedFileName[:gcm.NonceSize()], encryptedFileName[gcm.NonceSize():])
	if err != nil {
		return "", err
	}

	return string(originalFileName), nil
}

func decryptFile(gcm cipher.AEAD, encryptedFilePath string) (string, error) {
	originalFileName, err := decryptFileName(gcm, encryptedFilePath)
	if err != nil {
		return "", err
	}

	encryptedFile, _ := os.Open(encryptedFilePath)
	defer encryptedFile.Close()

	// skip salt
	encryptedFile.Seek(saltSize, io.SeekStart)

	// get lengthInBytes of encryptedFileName
	lengthInBytes := make([]byte, 8)
	encryptedFile.Read(lengthInBytes)
	intLength := binary.BigEndian.Uint64(lengthInBytes)

	// skip encryptedFileName
	encryptedFile.Seek(int64(intLength), io.SeekCurrent)

	originalFilePath := fileutil.GetPathToFile(encryptedFilePath) + originalFileName
	originalFile, _ := os.OpenFile(originalFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer originalFile.Close()
	writer := bufio.NewWriter(originalFile)
	defer writer.Flush()

	reader := bufio.NewReader(encryptedFile)

	encryptedChunk := make([]byte, chunkForEncryptedFile)
	for {
		n, err := reader.Read(encryptedChunk)
		if err == io.EOF {
			break
		}

		// ignore err here cause if file name is decrypted successfully and move to here
		// which means the key is valid
		originalChunk, _ := decrypt(gcm, encryptedChunk[:gcm.NonceSize()], encryptedChunk[gcm.NonceSize():n])
		writer.Write(originalChunk)

		logMemory()
	}

	return originalFilePath, nil
}

func Unlock(passphrase, encryptedFilePath string) (string, bool) {
	salt := getSaltFromEncryptedFile(encryptedFilePath)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	originalFile, err := decryptFile(gcm, encryptedFilePath)
	if err != nil {
		return "[-] Invalid passphrase", false
	}
	os.Remove(encryptedFilePath)

	return originalFile, true
}
