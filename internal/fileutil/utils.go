package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	identifierExtension = ".locked"
)

func GetPathToFile(filePath string) string {
	pathToFile, _ := filepath.Split(filePath)
	return pathToFile
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
