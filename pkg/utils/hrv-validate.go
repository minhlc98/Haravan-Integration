package utils

import (
	"crypto/hmac"
	"os"

	"github.com/gofiber/fiber/v3"
)

func ValidateHaravanWebhook(c fiber.Ctx) bool {
	topic := c.Get("X-Haravan-Topic")
	signature := c.Get("X-Haravan-Hmacsha256")
	orgid := c.Get("X-Haravan-Org-Id")
	if topic == "" || signature == "" || orgid == "" {
		return false
	}
	sh := CreateHmacSignatureBase64(c.Body(), os.Getenv("APP_SECRET"))
	return hmac.Equal([]byte(sh), []byte(signature)) 
}