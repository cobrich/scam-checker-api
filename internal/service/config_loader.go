package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type ConfigLoader struct {
	repo *repository.ThreatRepository
}

func NewConfigLoader(repo *repository.ThreatRepository) *ConfigLoader {
	return &ConfigLoader{repo: repo}
}

// LoadAll загружает все настройки из БД в структуру
func (l *ConfigLoader) LoadAll(ctx context.Context) (*domain.AppConfig, error) {
	cfg := &domain.AppConfig{}
	var err error

	// 1. Brands
	cfg.Brands, err = l.repo.GetBrands(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load brands: %w", err)
	}

	// 2. Keywords
	cfg.Keywords, err = l.repo.GetKeywords(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load keywords: %w", err)
	}

	// 3. TLDs
	cfg.TLDs, err = l.repo.GetTLDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLDs: %w", err)
	}

	// 4. Shorteners
	cfg.Shorteners, err = l.repo.GetShorteners(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load shorteners: %w", err)
	}

	// 5. Geo Risks
	cfg.GeoRisks, err = l.repo.GetGeoRisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load geo risks: %w", err)
	}

	// 6. Hosting
	cfg.Hosting, err = l.repo.GetHosting(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load hosting: %w", err)
	}

	slog.Info("Configuration loaded from DB", 
		"brands", len(cfg.Brands),
		"keywords", len(cfg.Keywords),
		"hosting_rules", len(cfg.Hosting),
	)

	return cfg, nil
}