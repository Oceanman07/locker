package locker

import (
	"unicode"

	"golang.org/x/term"
)

func GetPassphrase() string {
	passphrase, _ := term.ReadPassword(0)
	return string(passphrase)
}

func hasOneNumber(passphrase string) bool {
	for _, char := range passphrase {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

func hasLowercase(passphrase string) bool {
	for _, char := range passphrase {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

func hasUppercase(passphrase string) bool {
	for _, char := range passphrase {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

func hasSpecialChar(passphrase string) bool {
	specialChars := "/()_-+*&^%$#@!:.?[]|~;="
	for _, specialChar := range specialChars {
		for _, char := range passphrase {
			if char == specialChar {
				return true
			}
		}
	}
	return false
}

func IsValidPassphrase(passphrase string) bool {
	if !hasOneNumber(passphrase) {
		return false
	}
	if !hasLowercase(passphrase) {
		return false
	}
	if !hasUppercase(passphrase) {
		return false
	}
	if !hasSpecialChar(passphrase) {
		return false
	}
	return true
}
