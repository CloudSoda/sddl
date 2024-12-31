//go:build !windows

package main

import (
	"errors"
)

// GetFileSecurityBase64 retrieves a file's security descriptor in base64-encoded format.
func GetFileSecurityBase64(filename string) (string, error) {
	return "", errors.New("not implemented on this platform")
}

// GetFileSDString retrieves a file's security descriptor as a SDDL string.
func GetFileSDString(filename string) (string, error) {
	return "", errors.New("not implemented on this platform")
}
