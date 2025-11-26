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

	// Читаем флаг full. Если ?full=true, то переменная будет true.
	// Если параметра нет или он другой, будет false.
	fullScan := c.Query("full") == "true"

	// Вызываем метод Analyze (бывший Check)
	report, err := h.checker.Analyze(c.Context(), urlToCheck, fullScan)
	if err != nil {
		// Логируем ошибку для себя, пользователю отдаем 500
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Проверяем формат
	if c.Query("format") == "apivoid" {
		apiVoidResp := ConvertToApiVoid(report)
		return c.JSON(apiVoidResp)
	}

	// Просто отдаем структуру отчета, Fiber сам превратит её в красивый JSON
	return c.JSON(report)
}
