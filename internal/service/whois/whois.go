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

// GetInfo makes rewuest to WHOIS server and parsing response
func (s *WhoisService) GetInfo(ctx context.Context, domainName string) *domain.WhoisInfo {
	type result struct {
		raw string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		raw, err := whois.Whois(domainName)
		ch <- result{raw, err}
	}()

	var raw string
	var err error

	select {
	case res := <-ch:
		raw = res.raw
		err = res.err
	case <-time.After(3 * time.Second):
		return nil
	case <-ctx.Done():
		return nil
	}

	if err != nil {
		return nil
	}

	// 1. Raw query
	raw, err = whois.Whois(domainName)
	if err != nil {
		return nil
	}

	// 2. Parsing
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return nil
	}

	info := &domain.WhoisInfo{
		Registrar:   parsed.Registrar.Name,
		CreatedDate: parsed.Domain.CreatedDate,
		ExpiresDate: parsed.Domain.ExpirationDate,
	}

	// 3. Calculate age
	if parsed.Domain.CreatedDate != "" {
		days := calculateAge(parsed.Domain.CreatedDate)
		info.DomainAgeDays = days
	}

	return info
}

func calculateAge(dateStr string) int {
	dateStr = strings.TrimSpace(dateStr)

	// list of fromats
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

	for _, format := range formats {
		if strings.Contains(dateStr, "(") && !strings.Contains(format, "(") {
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

	if err != nil {
		return 0
	}

	return int(time.Since(t).Hours() / 24)
}
