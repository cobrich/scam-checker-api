package main

import (
	"context"
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
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/geoip2-golang"
)

func main() {
	// 1. Инициализация логгера
	logger.Setup()
	slog.Info("Starting Scam Checker API...")

	// 2. Конфиг
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Ошибка загрузки конфига", "error", err)
		os.Exit(1)
	}

	// 3. Подключение к БД (Retry Loop)
	ctx := context.Background()
	var dbPool *pgxpool.Pool

	for i := 0; i < 10; i++ {
		dbPool, err = pgxpool.New(ctx, cfg.PostgresURL)
		if err == nil {
			if err = dbPool.Ping(ctx); err == nil {
				break
			}
		}
		slog.Info("Попытка подключения к БД...", "attempt", i+1, "error", err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		slog.Error("Не удалось подключиться к БД", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()
	slog.Info("Успешное подключение к Postgres!")

	// 4. GeoIP (Безопасная инициализация)
	var cityDB, asnDB *geoip2.Reader

	if db, err := geoip2.Open("GeoLite2-City.mmdb"); err != nil {
		slog.Warn("GeoLite2-City.mmdb not found. GeoIP features disabled.")
	} else {
		cityDB = db
	}

	if db, err := geoip2.Open("GeoLite2-ASN.mmdb"); err != nil {
		slog.Warn("GeoLite2-ASN.mmdb not found. Hosting analysis disabled.")
	} else {
		asnDB = db
	}

	// Безопасное закрытие (проверка на nil)
	defer func() {
		if cityDB != nil {
			cityDB.Close()
		}
		if asnDB != nil {
			asnDB.Close()
		}
	}()

	// 5. Инициализация слоев
	threatRepo := repository.NewThreatRepository(dbPool)

	// Сервисы
	whitelistService := service.NewWhitelistService(ctx, threatRepo)
	infraService := infra.NewInfraService(cityDB, asnDB)
	checkerService := service.NewCheckerService(threatRepo, whitelistService, infraService)

	// 6. Запуск Фетчеров
	shouldRunFetchers := cfg.EnableFetchers == "true"

	if shouldRunFetchers {
		slog.Info("Запуск фоновых обновлений баз...")
		phishService := fetcher.NewPhishTankService(threatRepo)
		urlHausService := fetcher.NewUrlHausService(threatRepo)
		openphishService := fetcher.NewOpenPhishService(threatRepo)
		threatfoxService := fetcher.NewThreatFoxService(threatRepo)

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

	// 7. Настройка Web Server
	app := fiber.New(fiber.Config{
		// Отключаем заголовок Server: Fiber (безопасность через неясность)
		DisableStartupMessage: true,
	})

	// Middlewares
	app.Use(recover.New()) // Восстановление после паники
	app.Use(cors.New())    // Разрешаем запросы с браузера

	// Custom Logger Middleware
	app.Use(func(c *fiber.Ctx) error {
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
		return err
	})

	// Rate Limiter
	app.Use(limiter.New(limiter.Config{
		Max:        60, // Увеличил до 60 (20 маловато для тестов)
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(fiber.Map{"error": "Too many requests"})
		},
	}))

	// 8. Роуты
	// Healthcheck (для Docker/K8s)
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(fiber.Map{"status": "ok"})
	})

	handler := rest.NewHandler(checkerService)
	handler.RegisterRoutes(app)

	// 9. Запуск и Graceful Shutdown
	go func() {
		slog.Info("Сервер запущен", "port", cfg.AppPort)
		if err := app.Listen(cfg.AppPort); err != nil {
			slog.Error("Ошибка сервера", "error", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	slog.Info("Gracefully shutting down...")

	// Даем серверу 5 секунд на завершение текущих запросов
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		slog.Error("Ошибка при выключении", "error", err)
	}
	slog.Info("Server stopped")
}
