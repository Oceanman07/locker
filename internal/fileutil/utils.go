package fileutil

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	identifierExtension = ".locked"
	rootPath            = "/"
	textType            = "text"
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

func IsRootPath(path string) bool {
	absolutePath, _ := filepath.Abs(path)
	return absolutePath == rootPath
}

func IsRegularFile(path string) bool {
	fileInfo, _ := os.Stat(path)
	if fileInfo.IsDir() {
		return false
	}
	return true
}

func IsTextFile(filePath string) bool {
	file, _ := os.Open(filePath)
	defer file.Close()

	buffer := make([]byte, 1024)
	n, _ := file.Read(buffer)
	buffer = buffer[:n]

	fileType := http.DetectContentType(buffer)
	return strings.HasPrefix(fileType, textType)
}

func IsTextContent(buffer []byte) bool {
	fileType := http.DetectContentType(buffer)
	return strings.HasPrefix(fileType, textType)
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
