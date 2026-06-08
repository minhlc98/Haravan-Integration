package utils

import (
	"crypto/hmac"
	"os"

	"github.com/gofiber/fiber/v3"
)

func ValidateHaravanWebhook(c fiber.Ctx) bool {
	signature := c.Get("X-Haravan-Hmac-Sha256")
	sh := CreateHmacSignatureBase64(c.Body(), os.Getenv("WEBHOOK_SECRET"))
	return hmac.Equal([]byte(sh), []byte(signature)) 
}