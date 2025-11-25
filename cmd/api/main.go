package main

import (
	"context"
	"fmt"
	"log"

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

	// 2. Подключение к БД (Пул соединений)
	ctx := context.Background()
	dbPool, err := pgxpool.New(ctx, cfg.PostgresURL)
	if err != nil {
		log.Fatalf("Не удалось подключиться к БД: %v", err)
	}
	defer dbPool.Close()

	// Проверка соединения
	if err := dbPool.Ping(ctx); err != nil {
		log.Fatalf("БД недоступна: %v", err)
	}
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
