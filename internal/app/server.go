package app

import (
	"log/slog"
	"time"

	"github.com/cobrich/scam-checker-api/config"
	"github.com/cobrich/scam-checker-api/internal/service"
	"github.com/cobrich/scam-checker-api/internal/transport/rest"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func NewServer(cfg *config.Config, checker *service.CheckerService) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReadTimeout:           10 * time.Second,
		WriteTimeout:          10 * time.Second,
	})

	// Middlewares
	app.Use(recover.New())
	app.Use(cors.New())
	app.Use(requestLogger())
	app.Use(rateLimiter())

	// Routes
	setupRoutes(app, checker)

	return app
}

func setupRoutes(app *fiber.App, checker *service.CheckerService) {
	// System enpoinds
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(fiber.Map{"status": "ok"})
	})
	app.Get("/favicon.ico", func(c *fiber.Ctx) error {
		return c.SendStatus(204)
	})

	// API endpoints
	handler := rest.NewHandler(checker)
	handler.RegisterRoutes(app)
}

func requestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		duration := time.Since(start)

		attrs := []any{
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Int("status", c.Response().StatusCode()),
			slog.String("ip", c.IP()),
			slog.String("duration", duration.String()),
		}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		slog.Info("http_request", attrs...)

		return nil
	}
}

func rateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        60,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(fiber.Map{"error": "Too many requests"})
		},
	})
}
