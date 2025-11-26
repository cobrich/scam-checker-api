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
	mu      sync.RWMutex // Мьютекс для потокобезопасности (если будешь обновлять список на лету)
	repo    *repository.ThreatRepository
}

func NewWhitelistService(ctx context.Context, repo *repository.ThreatRepository) *WhitelistService {
	// Инициализируем карту
	ws := &WhitelistService{
		domains: make(map[string]bool),
		repo:    repo,
	}

	// Загружаем данные из БД при старте
	if err := ws.Refresh(ctx); err != nil {
		slog.Error("⚠️ Ошибка загрузки Whitelist из БД: %v. Использую пустой список.\n",
			"error", err,
		)
	} else {
		slog.Info("✅ Whitelist загружен: \n",
			"доменов", len(ws.domains),
		)
	}

	return ws
}

// Refresh обновляет данные из БД (можно вызывать периодически)
func (s *WhitelistService) Refresh(ctx context.Context) error {
	// Ставим таймаут, чтобы не зависнуть при старте
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	list, err := s.repo.GetWhitelist(ctx)
	if err != nil {
		return err
	}

	// Создаем новую карту
	newMap := make(map[string]bool)
	for _, d := range list {
		newMap[d] = true
	}

	// Подменяем карту атомарно (Thread-safe)
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

	// Проверяем точное совпадение (google.com)
	if s.domains[hostname] {
		return true
	}

	// Проверяем родительский домен (docs.google.com -> ищем google.com)
	// Это простая реализация, разбиваем по точкам
	parts := strings.Split(hostname, ".")
	if len(parts) > 2 {
		// Собираем последние две части: google.com
		rootDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if s.domains[rootDomain] {
			return true
		}
	}

	// P.S. Для идеальной работы с доменами типа .co.uk лучше использовать
	// библиотеку "golang.org/x/net/publicsuffix"

	return false
}
