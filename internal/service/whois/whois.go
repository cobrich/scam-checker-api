package whois

import (
	"context"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type WhoisService struct{}

func NewWhoisService() *WhoisService {
	return &WhoisService{}
}

// GetInfo делает запрос к WHOIS серверу и парсит ответ
func (s *WhoisService) GetInfo(ctx context.Context, domainName string) *domain.WhoisInfo {
	// WHOIS часто тормозит, поэтому важно иметь таймаут.
	// Сама библиотека whois не поддерживает context напрямую в простой функции,
	// но мы можем обернуть вызов (или просто надеяться на быстрый ответ, обычно 2-3 сек).

	// 1. Делаем Raw запрос (получаем текст)
	raw, err := whois.Whois(domainName)
	if err != nil {
		return nil // Не удалось получить данные (или бан по IP)
	}

	// 2. Парсим текст в структуру
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return nil
	}

	info := &domain.WhoisInfo{
		Registrar:   parsed.Registrar.Name,
		CreatedDate: parsed.Domain.CreatedDate,
		ExpiresDate: parsed.Domain.ExpirationDate,
	}

	// 3. Считаем возраст в днях
	if parsed.Domain.CreatedDate != "" {
		// Парсер возвращает дату в разных форматах, но библиотека старается привести к стандарту RFC3339
		// Обычно формат: "2023-10-25T14:00:00Z"
		t, err := time.Parse(time.RFC3339, parsed.Domain.CreatedDate)

		// Если стандартный парсинг не прошел, пробуем упрощенный (иногда бывает просто дата)
		if err != nil {
			t, err = time.Parse("2006-01-02", parsed.Domain.CreatedDate)
		}

		if err == nil {
			days := int(time.Since(t).Hours() / 24)
			info.DomainAgeDays = days
		}
	}

	return info
}
