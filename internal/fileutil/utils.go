package fileutil

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	identifierExtension = ".locked"
	rootPath            = "/"
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

	// get the first 1024 bytes to test
	buffer := make([]byte, 1024)
	n, _ := file.Read(buffer)
	buffer = buffer[:n]

	// if the text file is too small, http.DetectContentType will not be able to detect
	tempBuf := make([]byte, 1024)
	for len(buffer) < 1024 {
		file.Seek(0, io.SeekStart)
		num, _ := file.Read(tempBuf)
		buffer = append(buffer, tempBuf[:num]...)
	}

	fileType := http.DetectContentType(buffer)
	return strings.HasPrefix(fileType, "text")
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
