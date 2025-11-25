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
	"github.com/cobrich/scam-checker-api/internal/transport/rest"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// 1. Загрузка конфига
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Ошибка конфига: %v", err)
	}

	// 2. Подключение к БД с повторными попытками (Retry Loop)
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

	fmt.Println("Успешное подключение к Postgres!")

	// 3. Инициализация слоев
	threatRepo := repository.NewThreatRepository(dbPool)

	phishService := fetcher.NewPhishTankService(threatRepo)
	urlHausService := fetcher.NewUrlHausService(threatRepo)
	checkerService := service.NewCheckerService(threatRepo)

	// 4. Запуск Фетчера (в отдельной горутине или просто для теста)
	// В будущем здесь будет HTTP сервер, а фетчер будет запускаться кроном
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

	app := fiber.New()

	app.Use(logger.New())

	handler := rest.NewHandler(checkerService)
	handler.RegisterRoutes(app)

	fmt.Printf("Сервер запущен на порту %s\n", cfg.AppPort)
	log.Fatal(app.Listen(cfg.AppPort))
}
