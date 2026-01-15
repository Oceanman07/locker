package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	identifierExtension    = ".locked"
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

func IsRegularFile(path string) bool {
	fileInfo, _ := os.Stat(path)
	if fileInfo.IsDir() {
		return false
	}
	return true
}

func ListDir(rootDir string, isRecursive bool) []string {
	var filePaths []string

	paths, _ := os.ReadDir(rootDir)
	for _, path := range paths {
		if path.IsDir() {
			if !isRecursive {
				continue
			}
			dirPath := filepath.Join(rootDir, path.Name())
			filePaths = append(filePaths, ListDir(dirPath, isRecursive)...)

		} else {
			filePath := filepath.Join(rootDir, path.Name())
			filePaths = append(filePaths, filePath)
		}
	}

	return filePaths
}

func FilterFiles(filePaths []string, isEncrypted bool) []string {
	var filterFiles []string
	for _, path := range filePaths {
		if isEncrypted {
			if strings.HasSuffix(path, identifierExtension) {
				filterFiles = append(filterFiles, path)
			}
		} else {
			if !strings.HasSuffix(path, identifierExtension) {
				filterFiles = append(filterFiles, path)
			}
		}
	}
	return filterFiles
}
