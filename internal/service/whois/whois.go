package whois

import (
	"context"
	"strings"
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
	// 1. Raw запрос
	raw, err := whois.Whois(domainName)
	if err != nil {
		return nil
	}

	// 2. Парсинг
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return nil
	}

	info := &domain.WhoisInfo{
		Registrar:   parsed.Registrar.Name,
		CreatedDate: parsed.Domain.CreatedDate,
		ExpiresDate: parsed.Domain.ExpirationDate,
	}

	// 3. Вычисление возраста (Умный парсинг)
	if parsed.Domain.CreatedDate != "" {
		days := calculateAge(parsed.Domain.CreatedDate)
		info.DomainAgeDays = days
	}

	return info
}

// calculateAge пытается распарсить дату разными способами
func calculateAge(dateStr string) int {
	// Очищаем строку от лишнего мусора, который бывает в WHOIS
	// Например: "2017-07-24 07:01:29 (GMT+0:00)" -> нас интересует начало
	dateStr = strings.TrimSpace(dateStr)

	// Список форматов, которые встречаются в дикой природе
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",           // ISO8601
		"2006-01-02 15:04:05",            // Common SQL style
		"2006-01-02",                     // Simple date
		"02.01.2006",                     // RU/KZ style
		"02-Jan-2006",                    // UK style
		"2006.01.02",                     // Dot style
		"Mon Jan 02 15:04:05 2006",       // Unix date
		"2006-01-02 15:04:05 (MST+0:00)", // Твой случай с Qazsport (.kz)
		"2006-01-02 15:04:05 +0000",
	}

	var t time.Time
	var err error

	// Пробуем форматы по очереди
	for _, format := range formats {
		// Для сложных форматов с таймзоной в скобках можно попробовать обрезать
		if strings.Contains(dateStr, "(") && !strings.Contains(format, "(") {
			// Попытка взять только дату "2017-07-24" из длинной строки
			if len(dateStr) >= 10 {
				t, err = time.Parse("2006-01-02", dateStr[:10])
				if err == nil {
					break
				}
			}
		}

		t, err = time.Parse(format, dateStr)
		if err == nil {
			break
		}
	}

	// Если ничего не подошло, возвращаем 0
	if err != nil {
		return 0
	}

	// Считаем дни
	return int(time.Since(t).Hours() / 24)
}
