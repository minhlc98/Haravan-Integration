package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"haravan-integration/pkg/utils"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
  if err != nil {
    log.Fatal("Error loading .env file")
  }

	app := fiber.New()

	app.Get("/install", install)

	app.Get("/install/callback", installCallback)

	app.Get("/webhooks", verifyWebhook)

	app.Post("/webhooks", handleWebhook)


	app.Get("/*", func(c fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	if err := app.Listen(":3000"); err != nil {
		log.Fatal("Error starting server:", err)
	}
}

func install(c fiber.Ctx) error {
	scopes := "openid profile email org userinfo grant_service wh_api com.write_products com.write_orders com.write_customers"

	u, _ := url.Parse("https://accounts.haravan.com/connect/authorize")
	q := u.Query()
	q.Set("response_mode", "query")
	q.Set("response_type", "code")
	q.Set("client_id", os.Getenv("APP_ID"))
	q.Set("scope", scopes)
	q.Set("redirect_uri", os.Getenv("REDIRECT_URI"))
	u.RawQuery = q.Encode()

	return c.Redirect().To(u.String())
}

func installCallback(c fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(400).SendString("missing code")
	}

	token, err := exchangeToken(code)
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	if err := subscribeWebhook(token.AccessToken); err != nil {
		return c.Status(500).SendString(err.Error())
	}

	return c.SendString("Installed OK. Scope: " + token.Scope)
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func exchangeToken(code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", os.Getenv("APP_ID"))
	form.Set("client_secret", os.Getenv("APP_SECRET"))
	form.Set("code", code)
	form.Set("redirect_uri", os.Getenv("REDIRECT_URI"))

	req, _ := http.NewRequest(
		"POST",
		"https://accounts.haravan.com/connect/token",
		bytes.NewBufferString(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("token error: %s", string(body))
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	fmt.Println("token:", token)

	return &token, nil
}

func subscribeWebhook(accessToken string) error {
	req, _ := http.NewRequest(
		"POST",
		"https://webhook.haravan.com/api/subscribe",
		bytes.NewBufferString(`{}`),
	)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("subscribe webhook error: %s", string(body))
	}

	log.Println("subscribe webhook:", string(body))
	return nil
}

func verifyWebhook(c fiber.Ctx) error {
	if c.Query("hub.verify_token") != os.Getenv("WEBHOOK_VERIFY_TOKEN") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid verify token",
		})
	}
	return c.SendString(c.Query("hub.challenge"))
}

func handleWebhook(c fiber.Ctx) error {
	if !utils.ValidateHaravanWebhook(c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid signature",
		})
	}
	log.Println("Webhook received:", string(c.Body()))
	return c.JSON(fiber.Map{
		"message": "Webhook received",
	})
}