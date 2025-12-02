package service

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type WhitelistService struct {
	domains map[string]bool
	mu      sync.RWMutex
	repo    *repository.ThreatRepository
}

func NewWhitelistService(ctx context.Context, repo *repository.ThreatRepository) *WhitelistService {
	ws := &WhitelistService{
		domains: make(map[string]bool),
		repo:    repo,
	}

	if err := ws.Refresh(ctx); err != nil {
		slog.Error("⚠️ Whitelist error",
			"error", err,
		)
	} else {
		slog.Info("✅ Whitelist loaded: \n",
			"found", len(ws.domains),
		)
	}

	return ws
}

// Refresh updates db (you can make periodically)
func (s *WhitelistService) Refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	list, err := s.repo.GetWhitelist(ctx)
	if err != nil {
		return err
	}

	newMap := make(map[string]bool)
	for _, d := range list {
		newMap[d] = true
	}

	s.mu.Lock()
	s.domains = newMap
	s.mu.Unlock()

	return nil
}

func (s *WhitelistService) IsWhitelisted(rawURL string) bool {
	hostname, err := utils.ExtractHostname(rawURL)
	if err != nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.domains[hostname] {
		return true
	}

	// Check paretn domain (docs.google.com -> search google.com)
	// Parse with dots
	parts := strings.Split(hostname, ".")
	if len(parts) > 2 {
		// The last to parts google.com
		rootDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if s.domains[rootDomain] {
			return true
		}
	}

	// P.S. For optimal performance with domains such as .co.uk, it is recommended to utilize
	// the “golang.org/x/net/publicsuffix” library.

	return false
}
