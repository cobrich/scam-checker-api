package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
