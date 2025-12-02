package config

import (
	"log/slog"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	PostgresURL    string
	RedisURL       string
	AppPort        string
	EnableFetchers string
}

func LoadConfig() (*Config, error) {
	// Load the .env file, if it exists (for local development)
	if err := godotenv.Load(); err != nil {
		// If the .env file does not exist (for example, in Docker we pass variables directly),
		// this should not be a critical error.
		// It is better to simply ignore the error or check os.IsNotExist
		slog.Info("No .env file found, using system environment variables")
	}

	cfg := &Config{
		PostgresURL:    os.Getenv("DATABASE_URL"), // postgres://user:pass@localhost:5432/dbnameRedisURL:
		RedisURL:       os.Getenv("REDIS_URL"),
		AppPort:        os.Getenv("APP_PORT"),
		EnableFetchers: os.Getenv("RUN_FETCHERS"),
	}

	if cfg.AppPort == "" {
		cfg.AppPort = ":8080"
	}

	return cfg, nil
}
