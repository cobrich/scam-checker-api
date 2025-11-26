package config

import (
	"log/slog"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	PostgresURL    string
	AppPort        string
	EnableFetchers string
}

func LoadConfig() (*Config, error) {
	// Загружаем .env файл, если он есть (для локальной разработки)
	if err := godotenv.Load(); err != nil {
		// Если файла .env нет (например, в Docker мы передаем переменные напрямую),
		// это не должно быть критической ошибкой.
		// Лучше просто проигнорировать ошибку или проверить os.IsNotExist
		// return nil, err  <-- Убери return, пусть программа продолжает работу
		slog.Info("No .env file found, using system environment variables")
	}

	cfg := &Config{
		PostgresURL:    os.Getenv("DATABASE_URL"), // postgres://user:pass@localhost:5432/dbname
		AppPort:        os.Getenv("APP_PORT"),
		EnableFetchers: os.Getenv("RUN_FETCHERS"),
	}

	if cfg.AppPort == "" {
		cfg.AppPort = ":8080"
	}

	return cfg, nil
}
