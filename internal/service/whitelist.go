package service

import (
	"strings"
	"sync"

	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
)

type WhitelistService struct {
	domains map[string]bool
	mu      sync.RWMutex // Мьютекс для потокобезопасности (если будешь обновлять список на лету)
}

func NewWhitelistService() *WhitelistService {
	// Инициализируем карту
	ws := &WhitelistService{
		domains: make(map[string]bool),
	}

	// Загружаем популярные домены (в реальности лучше грузить из файла/БД)
	topDomains := []string{
		"google.com", "youtube.com", "facebook.com", "instagram.com",
		"twitter.com", "wikipedia.org", "whatsapp.com", "amazon.com",
		"vk.com", "yandex.ru", "sberbank.ru", "mail.ru", "t.me",
		"github.com", "stackoverflow.com", "microsoft.com", "apple.com",
	}

	for _, d := range topDomains {
		ws.domains[d] = true
	}

	return ws
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
