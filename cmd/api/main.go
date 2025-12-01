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

	"github.com/robfig/cron/v3"
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

	configLoader := service.NewConfigLoader(threatRepo) // threatRepo уже имеет методы конфига
	appConfig, err := configLoader.LoadAll(ctx)
	if err != nil {
		slog.Error("Failed to load config from DB", "error", err)
		// Можно упасть, а можно продолжить с пустым конфигом (но лучше упасть)
		os.Exit(1)
	}

	// Сервисы
	whitelistService := service.NewWhitelistService(ctx, threatRepo)
	infraService := infra.NewInfraService(cityDB, asnDB, appConfig)
	checkerService := service.NewCheckerService(threatRepo, whitelistService, infraService, appConfig)

	// 6. Запуск Фетчеров
	shouldRunFetchers := cfg.EnableFetchers == "true"

	phishService := fetcher.NewPhishTankService(threatRepo)
	urlHausService := fetcher.NewUrlHausService(threatRepo)
	openphishService := fetcher.NewOpenPhishService(threatRepo)
	threatfoxService := fetcher.NewThreatFoxService(threatRepo)

	if shouldRunFetchers {
		slog.Info("Запуск планировщика задач...")

		c := cron.New()

		runJob := func(name string, job func(context.Context) error) {
			slog.Info("Запуск задачи", "job", name)
			if err := job(context.Background()); err != nil {
				slog.Error("Ошибка задачи", "job", name, "error", err)
			} else {
				slog.Info("Задача выполнена успешно", "job", name)
			}
		}

		// PhishTank (каждый час)
		c.AddFunc("@hourly", func() {
			runJob("PhishTank", phishService.Run)
		})

		// URLhaus (каждые 30 минут)
		c.AddFunc("@every 30m", func() {
			runJob("URLhaus", urlHausService.Run)
		})

		// OpenPhish (каждые 2 часа)
		c.AddFunc("@every 12h", func() {
			runJob("OpenPhish", openphishService.Run)
		})

		// ThreatFox (каждые 4 часа)
		c.AddFunc("@every 1h", func() {
			runJob("ThreatFox", threatfoxService.Run)
		})

		c.Start()

		// ВАЖНО: Запускаем обновление прямо сейчас (при старте), чтобы не ждать час
		// Делаем это в горутинах, чтобы не блокировать запуск сервера
		go runJob("PhishTank (Init)", phishService.Run)
		go runJob("URLhaus (Init)", urlHausService.Run)
		go runJob("OpenPhish (Init)", openphishService.Run)
		go runJob("ThreatFox (Init)", threatfoxService.Run)
	}

	// 7. Настройка Web Server
	app := fiber.New(fiber.Config{
		// Отключаем заголовок Server: Fiber (безопасность через неясность)
		DisableStartupMessage: true,
	})

	// Middlewares
	app.Use(recover.New()) // Восстановление после паники
	app.Use(cors.New())    // Разрешаем запросы с браузера

	// Auth
	// Можно включить но надо будет раскоментировать API_KEY в docker-compose.
	// app.Use(func(c *fiber.Ctx) error {
	// 	// Читаем заголовок Authorization или параметр ?key=
	// 	key := c.Get("X-API-Key")
	// 	if key == "" {
	// 		key = c.Query("key")
	// 	}

	// 	// Сравниваем с секретным ключом из ENV
	// 	// В docker-compose.yml добавь: API_SECRET=my_super_secret_password
	// 	secret := os.Getenv("API_SECRET")
	// 	if secret == "" {
	// 		// Если секрет не задан, разрешаем всем (для тестов), но лучше паниковать
	// 		return c.Next()
	// 	}

	// 	if key != secret {
	// 		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	// 	}

	// 	return c.Next()
	// })

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
