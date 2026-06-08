package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func CreateHmacSignatureBase64(data []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	sh := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return sh
}