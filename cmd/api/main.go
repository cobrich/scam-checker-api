package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cobrich/scam-checker-api/config"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service"
	"github.com/cobrich/scam-checker-api/internal/service/fetcher"
	"github.com/cobrich/scam-checker-api/internal/service/infra"
	"github.com/cobrich/scam-checker-api/internal/transport/rest"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/oschwald/geoip2-golang"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
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

		log.Printf("Попытка подключения к БД (%d/10) неудачна: %v. Ждем 2 сек...", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("Не удалось подключиться к БД после всех попыток: %v", err)
	}
	defer dbPool.Close()

	// Инициализируем City базу
	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		fmt.Println("⚠️ Warning: GeoLite2-City.mmdb not found. GeoIP features disabled.")
	}

	// Инициализируем ASN базу
	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Println("⚠️ Warning: GeoLite2-ASN.mmdb not found. Hosting analysis disabled.")
	}
	defer func() {
		cityDB.Close()
		asnDB.Close()
	}()

	fmt.Println("Успешное подключение к Postgres!")

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
				log.Printf("Ошибка фетчера: %v", err)
			}
		}()

		go func() {
			if err := urlHausService.Run(ctx); err != nil {
				log.Printf("Ошибка фетчера: %v", err)
			}
		}()
		go func() {
			if err := openphishService.Run(ctx); err != nil {
				log.Printf("Ошибка фетчера: %v", err)
			}
		}()

		go func() {
			if err := threatfoxService.Run(ctx); err != nil {
				log.Printf("Ошибка фетчера: %v", err)
			}
		}()
	}

	app := fiber.New()

	app.Use(logger.New())

	handler := rest.NewHandler(checkerService)
	handler.RegisterRoutes(app)

	fmt.Printf("Сервер запущен на порту %s\n", cfg.AppPort)
	log.Fatal(app.Listen(cfg.AppPort))
}
