package fileutil

import (
	"errors"
	"os"
)

const (
	oneShotForOriginalSize = 50 * 1024 * 1024 // one shot for <= 50MB file
	// the exact 50MB file after encrypting will be salt(16bytes) + nonce(12bytes) + encryptedData(remained 50MB) + tag(16bytes)
	oneShotForEncryptedSize = 16 + 12 + oneShotForOriginalSize + 16
)

func IsSmallFile(filePath string, isEncrypted bool) bool {
	fileSize := GetFileSize(filePath)
	if isEncrypted {
		return fileSize <= oneShotForEncryptedSize
	}
	return fileSize <= oneShotForOriginalSize
}

func GetFileSize(filePath string) int {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return int(fileInfo.Size())
}

func IsExist(path string) bool {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
