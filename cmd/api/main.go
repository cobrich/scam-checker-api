package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cobrich/scam-checker-api/config"
	"github.com/cobrich/scam-checker-api/internal/pkg/logger"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service"
	"github.com/cobrich/scam-checker-api/internal/service/fetcher"
	"github.com/cobrich/scam-checker-api/internal/service/infra"
	"github.com/cobrich/scam-checker-api/internal/transport/rest"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/oschwald/geoip2-golang"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	logger.Setup()
	slog.Info("Starting Scam Checker API...")

	// Загрузка конфига
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Ошибка конфига: %v", err)
	}

	// Подключение к БД с повторными попытками (Retry Loop)
	ctx := context.Background()
	var dbPool *pgxpool.Pool

	// Пробуем подключиться 10 раз с паузой 2 секунды
	for i := 0; i < 10; i++ {
		dbPool, err = pgxpool.New(ctx, cfg.PostgresURL)
		if err == nil {
			// Если создали пул, проверяем пинг
			if err = dbPool.Ping(ctx); err == nil {
				break // Успех! Выходим из цикла
			}
		}

		slog.Info("Попытка подключения к БД (%d/10) неудачна: %v. Ждем 2 сек...",
			"", i+1,
			"error", err,
		)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("Не удалось подключиться к БД после всех попыток: %v", err)
	}
	defer dbPool.Close()

	// Инициализируем City базу
	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		slog.Error("⚠️ Warning: GeoLite2-City.mmdb not found. GeoIP features disabled.")
	}

	// Инициализируем ASN базу
	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		slog.Error("⚠️ Warning: GeoLite2-ASN.mmdb not found. Hosting analysis disabled.")
	}
	defer func() {
		cityDB.Close()
		asnDB.Close()
	}()

	slog.Info("Успешное подключение к Postgres!")

	// Dangerous Urls
	threatRepo := repository.NewThreatRepository(dbPool)

	// Fetching Urls from API's
	phishService := fetcher.NewPhishTankService(threatRepo)
	urlHausService := fetcher.NewUrlHausService(threatRepo)
	openphishService := fetcher.NewOpenPhishService(threatRepo)
	threatfoxService := fetcher.NewThreatFoxService(threatRepo)

	// Ligitimate Urls
	whitelistService := service.NewWhitelistService(ctx, threatRepo)

	// Network Rules
	infraService := infra.NewInfraService(cityDB, asnDB)

	// The orchestrator
	checkerService := service.NewCheckerService(threatRepo, whitelistService, infraService)

	// Запуск Фетчеров (в отдельной горутине или просто для теста)
	if false {
		go func() {
			if err := phishService.Run(ctx); err != nil {
				slog.Info("Ошибка фетчера: %v",
					"error", err,
				)
			}
		}()

		go func() {
			if err := urlHausService.Run(ctx); err != nil {
				slog.Info("Ошибка фетчера: %v",
					"error", err,
				)
			}
		}()
		go func() {
			if err := openphishService.Run(ctx); err != nil {
				slog.Info("Ошибка фетчера: %v",
					"error", err,
				)
			}
		}()

		go func() {
			if err := threatfoxService.Run(ctx); err != nil {
				slog.Info("Ошибка фетчера: %v",
					"error", err,
				)
			}
		}()
	}

	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()

		// Обрабатываем запрос
		err := c.Next()

		duration := time.Since(start)

		// Собираем атрибуты для лога
		attrs := []any{
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Int("status", c.Response().StatusCode()),
			slog.String("ip", c.IP()),
			slog.String("duration", duration.String()),
		}

		// Если была ошибка, добавляем её в лог
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}

		slog.Info("http_request", attrs...)
		return err
	})

	handler := rest.NewHandler(checkerService)
	app.Use(limiter.New(limiter.Config{
		Max:        20,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Лимит по IP
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(fiber.Map{
				"error": "Too many requests. Chill out.",
			})
		},
	}))
	handler.RegisterRoutes(app)

	slog.Info("Сервер запущен:",
		"port", cfg.AppPort,
	)

	// Запуск сервера в горутине
	go func() {
		if err := app.Listen(cfg.AppPort); err != nil {
			log.Panic(err)
		}
	}()

	// Ждем сигнала выключения (Ctrl+C или Docker stop)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c // Блокируем, пока не придет сигнал
	slog.Info("Gracefully shutting down...")
	_ = app.Shutdown()
	slog.Info("Server stopped")
}
