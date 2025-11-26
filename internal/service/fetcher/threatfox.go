package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type ThreatFoxService struct {
	repo *repository.ThreatRepository
}

func NewThreatFoxService(repo *repository.ThreatRepository) *ThreatFoxService {
	return &ThreatFoxService{repo: repo}
}

// Структура одной записи внутри массива
type ThreatFoxItem struct {
	IocValue   string `json:"ioc_value"`
	IocType    string `json:"ioc_type"`
	ThreatType string `json:"threat_type"`
}

func (s *ThreatFoxService) Run(ctx context.Context) error {
	url := "https://threatfox.abuse.ch/export/json/recent/"
	fmt.Println("Запуск обновления ThreatFox...")

	client := &http.Client{Timeout: 120 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ScamChecker-Bot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("ThreatFox API returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %v", err)
	}

	// ВАЖНО: Парсим как карту, где ключ = ID (строка)
	var data map[string][]ThreatFoxItem

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		// Если ошибка, выводим превью для отладки
		preview := string(bodyBytes)
		if len(preview) > 100 {
			preview = preview[:100]
		}
		return fmt.Errorf("ThreatFox JSON decode error: %v. Body: %s", err, preview)
	}

	batch := make([]domain.Threat, 0, 1000)
	count := 0

	// Проходим по карте (key = ID угрозы)
	for id, items := range data {
		for _, item := range items {
			// Берем URL и Домены. IP пропускаем (ip:port), так как наш чекер для ссылок.
			if item.IocType != "url" && item.IocType != "domain" {
				continue
			}

			threat := domain.Threat{
				URL:        item.IocValue,
				Source:     "threatfox",
				ExternalID: id, // ID берем из ключа карты
				Type:       item.ThreatType,
			}
			batch = append(batch, threat)
			count++

			if len(batch) >= 1000 {
				s.repo.SaveBatch(ctx, batch)
				batch = batch[:0]
			}
		}
	}
	if len(batch) > 0 {
		s.repo.SaveBatch(ctx, batch)
	}

	fmt.Printf("=== ThreatFox ЗАВЕРШЕН: %d записей загружено ===\n", count)
	return nil
}
