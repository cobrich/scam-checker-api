package rest

import (
	"github.com/cobrich/scam-checker-api/internal/service"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	checker *service.CheckerService
}

func NewHandler(checker *service.CheckerService) *Handler {
	return &Handler{checker: checker}
}

func (h *Handler) RegisterRoutes(app *fiber.App) {
	api := app.Group("/api")
	api.Get("/check", h.CheckURL)
}

func (h *Handler) CheckURL(c *fiber.Ctx) error {
	urlToCheck := c.Query("url")
	if urlToCheck == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "URL parameter is required",
		})
	}

	report, err := h.checker.Analyze(c.Context(), urlToCheck)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	return c.JSON(report)
}
