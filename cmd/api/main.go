package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cobrich/scam-checker-api/config"
	"github.com/cobrich/scam-checker-api/internal/app"
	"github.com/cobrich/scam-checker-api/internal/pkg/logger"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service"
	"github.com/cobrich/scam-checker-api/internal/service/cache"
	"github.com/cobrich/scam-checker-api/internal/service/infra"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/geoip2-golang"
)

func main() {
	// Logger
	logger.Setup()
	slog.Info("Starting Scam Checker API...")

	// Config
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Error loading config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Database
	dbPool := connectDB(ctx, cfg.PostgresURL)
	defer dbPool.Close()

	// GeoIP
	cityDB, asnDB := loadGeoIP()
	defer func() {
		if cityDB != nil {
			cityDB.Close()
		}
		if asnDB != nil {
			asnDB.Close()
		}
	}()

	// Redis
	var redisCache *cache.RedisCache
	if cfg.RedisURL != "" {
		r, err := cache.NewRedisCache(cfg.RedisURL, 10*time.Minute) // TTL 10 minutes
		if err != nil {
			slog.Error("Redis connection failed", "error", err)
			// if you want to continue without redis comment next line(current+1)
			// os.Exit(1)
		} else {
			redisCache = r
			slog.Info("Connected to Redis")
			defer redisCache.Close()
		}
	}

	// Main urls repo
	threatRepo := repository.NewThreatRepository(dbPool)

	// All config tables
	configLoader := service.NewConfigLoader(threatRepo)
	appConfig, err := configLoader.LoadAll(ctx)
	if err != nil {
		slog.Error("Failed to load config from DB", "error", err)
		// os.Exit(1)
	}

	// Services
	whitelistService := service.NewWhitelistService(ctx, threatRepo)
	infraService := infra.NewInfraService(cityDB, asnDB, appConfig)                                                // network part analyzer
	checkerService := service.NewCheckerService(threatRepo, whitelistService, infraService, appConfig, redisCache) // main orchestrator

	// Start Workers
	app.StartBackgroudJobs(ctx, threatRepo, cfg.EnableFetchers == "true")

	// Start Server
	server := app.NewServer(cfg, checkerService)

	go func() {
		slog.Info("Server started", "port", cfg.AppPort)
		if err := server.Listen(cfg.AppPort); err != nil {
			slog.Error("Server error", "error", err)
		}
	}()

	// Graceful Shutdown
	waitForShutdown(server)
}

func connectDB(ctx context.Context, url string) *pgxpool.Pool {
	for i := 0; i < 10; i++ {
		pool, err := pgxpool.New(ctx, url)
		if err == nil && pool.Ping(ctx) == nil {
			slog.Info("Connected to Postgres")
			return pool
		}
		slog.Info("Waiting for DB...", "attempt", i+1)
		time.Sleep(2 * time.Second)
	}
	slog.Error("Could not connect to DB")
	os.Exit(1)
	return nil
}

func loadGeoIP() (*geoip2.Reader, *geoip2.Reader) {
	city, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		slog.Warn("GeoLite2-City.mmdb not found. GeoIP features disabled.")
	}

	asn, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		slog.Warn("GeoLite2-ASN.mmdb not found. Hosting analysis disabled.")
	}
	return city, asn
}

func waitForShutdown(server *fiber.App) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	slog.Info("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.ShutdownWithContext(shutdownCtx); err != nil {
		slog.Error("Error while Shutdown", "error", err)
	}
	slog.Info("Server stopped")
}
