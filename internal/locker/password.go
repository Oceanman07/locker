package locker

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const mininalLength = 4

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

func isValidLength(passphrase string) bool {
	return utf8.RuneCountInString(passphrase) >= mininalLength
}

func IsValidPassphrase(passphrase string) bool {
	if !isValidLength(passphrase) {
		return false
	}
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
