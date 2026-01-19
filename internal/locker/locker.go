package locker

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

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

func encryptToNewFile(gcm cipher.AEAD, salt []byte, originalFilePath string) string {
	// naming encrypted file with salt to prevent
	// accidentally change the file name if encrypted file name is placed as file name which will fail decryption
	// reach over 255 chars limit when naming file
	// now the file name doesnt effect at all even if one char is changed or renamed completely
	newFileName := hex.EncodeToString(salt) + IdentifierExtension
	newFilePath := fileutil.GetPathToFile(originalFilePath) + newFileName

	// write to encrypted file
	encryptedFile, _ := os.OpenFile(newFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer encryptedFile.Close()
	writer := bufio.NewWriter(encryptedFile)
	defer writer.Flush()

	encryptedFileName, encryptedFileNameLength := encryptFileName(gcm, originalFilePath)
	writer.Write(salt)
	writer.Write(encryptedFileNameLength)
	writer.Write(encryptedFileName)

	// read from original file
	originalFile, _ := os.Open(originalFilePath)
	defer originalFile.Close()
	reader := bufio.NewReader(originalFile)

	// if dst argument of gcm.Seal/Open is nil, it will allocate new slice every time
	// 100 loops -> 100 allocations
	// -> preallocate once
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
	}

	return newFileName
}

func encryptToText(gcm cipher.AEAD, originalFilePath string) (string, error) {
	if !fileutil.IsTextFile(originalFilePath) {
		return "", errors.New("[-] Not a text file")
	}

	// text content for printing to the console
	var result string

	originalFile, _ := os.Open(originalFilePath)
	defer originalFile.Close()
	reader := bufio.NewReader(originalFile)

	// if dst argument of gcm.Seal/Open is nil, it will allocate new slice every time
	// 100 loops -> 100 allocations
	// -> preallocate once
	preallocateBufferForDst := make([]byte, 0, chunkForNormalFile+gcm.Overhead())

	chunk := make([]byte, chunkForNormalFile)
	for {
		n, err := reader.Read(chunk)
		if err == io.EOF {
			break
		}

		nonce := getNonceForGCM()
		encryptedChunk := gcm.Seal(preallocateBufferForDst, nonce, chunk[:n], nil)
		result = result + hex.EncodeToString(encryptedChunk)
	}

	return "\n" + result, nil
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

func Lock(passphrase, filePath string, overWriteWithGarbagePasses int, keepAfterLock, lockAsText bool) (string, error) {
	salt := make([]byte, saltSize)
	rand.Read(salt)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	var result string
	if lockAsText {
		encryptedFile, err := encryptToText(gcm, filePath)
		if err != nil {
			return "", err
		}
		result = encryptedFile
	} else {
		encryptedFile := encryptToNewFile(gcm, salt, filePath)
		result = encryptedFile
	}

	if !keepAfterLock {
		if !lockAsText {
			overWriteWithGarbage(filePath, overWriteWithGarbagePasses)
			os.Remove(filePath)
		}
	}

	return result, nil
}

func getSaltFromEncryptedFile(encryptedFilePath string) []byte {
	salt := make([]byte, saltSize)

	file, _ := os.Open(encryptedFilePath)
	defer file.Close()

	file.Read(salt)
	return salt
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

	dst := make([]byte, 0, len(encryptedFileName)-gcm.NonceSize()-gcm.Overhead())
	originalFileName, err := gcm.Open(dst, encryptedFileName[:gcmNoneSize], encryptedFileName[gcmNoneSize:], nil)
	if err != nil {
		return "", err
	}

	return string(originalFileName), nil
}

func decryptToNewFile(gcm cipher.AEAD, encryptedFilePath string) (string, error) {
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

	// write to decrypted file
	originalFilePath := fileutil.GetPathToFile(encryptedFilePath) + originalFileName
	originalFile, _ := os.OpenFile(originalFilePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	defer originalFile.Close()
	writer := bufio.NewWriter(originalFile)
	defer writer.Flush()

	// read from encrypted file
	reader := bufio.NewReader(encryptedFile)

	// if dst argument of gcm.Seal/Open is nil, it will allocate new slice every time
	// 100 loops -> 100 allocations
	// -> preallocate once
	preallocateBufferForDst := make([]byte, 0, chunkForNormalFile)

	encryptedChunk := make([]byte, chunkForEncryptedFile)
	for {
		n, err := reader.Read(encryptedChunk)
		if err == io.EOF {
			break
		}
		// ignore err here cause if file name is decrypted successfully and move to here
		// which means the key is valid
		originalChunk, _ := gcm.Open(preallocateBufferForDst, encryptedChunk[:gcmNoneSize], encryptedChunk[gcmNoneSize:n], nil)
		writer.Write(originalChunk)
	}

	return originalFilePath, nil
}

// This is helpful for file like passwords.txt
// instead of unlocking the secret file then locking again
// this allows to unlock file content then print to the consloe
// while keeping the locked secret file
func decryptToText(gcm cipher.AEAD, encryptedFilePath string) (string, error) {
	originalFileName, err := decryptFileName(gcm, encryptedFilePath)
	if err != nil {
		return "", err
	}

	// text content for printing to the console
	var result string

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

	// read from encrypted file
	reader := bufio.NewReader(encryptedFile)

	// if dst argument of gcm.Seal/Open is nil, it will allocate new slice every time
	// 100 loops -> 100 allocations
	// -> preallocate once
	preallocateBufferForDst := make([]byte, 0, chunkForNormalFile)

	encryptedChunk := make([]byte, chunkForEncryptedFile)
	for {
		n, err := reader.Read(encryptedChunk)
		if err == io.EOF {
			break
		}
		// ignore err here cause if file name is decrypted successfully and move to here
		// which means the key is valid
		originalChunk, _ := gcm.Open(preallocateBufferForDst, encryptedChunk[:gcmNoneSize], encryptedChunk[gcmNoneSize:n], nil)
		result = result + string(originalChunk)
	}
	result = "\n" + result + "\n----------\n" + "from file: " + originalFileName

	return result, nil
}

func Unlock(passphrase, encryptedFilePath string, keepAfterUnlock, unlockAsText bool) (string, error) {
	salt := getSaltFromEncryptedFile(encryptedFilePath)

	key := driveKey([]byte(passphrase), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	var result string
	if unlockAsText {
		originalFile, err := decryptToText(gcm, encryptedFilePath)
		if err != nil {
			return "", errors.New("[-] Invalid passphrase")
		}
		result = originalFile

	} else {
		originalFile, err := decryptToNewFile(gcm, encryptedFilePath)
		if err != nil {
			return "", errors.New("[-] Invalid passphrase")
		}
		result = originalFile
	}

	if !keepAfterUnlock {
		if !unlockAsText {
			os.Remove(encryptedFilePath)
		}
	}

	return result, nil
}
