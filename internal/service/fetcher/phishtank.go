package fetcher

import (
	"compress/gzip" // <--- ВАЖНО
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type PhishTankService struct {
	repo *repository.ThreatRepository
}

func NewPhishTankService(repo *repository.ThreatRepository) *PhishTankService {
	return &PhishTankService{repo: repo}
}

type phishTankEntry struct {
	PhishID int    `json:"phish_id"`
	URL     string `json:"url"`
}

func (s *PhishTankService) Run(ctx context.Context) error {
	url := "https://data.phishtank.com/data/online-valid.json"
	fmt.Println("Запуск обновления PhishTank...")

	client := &http.Client{Timeout: 120 * time.Second} // Увеличим таймаут, файл большой
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "scam-checker-bot/1.0")
	// Явно просим сжатие (хороший тон)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("PhishTank server error: %d", resp.StatusCode)
	}

	// --- МАГИЯ GZIP ---
	var reader io.ReadCloser
	// Проверяем, сжал ли сервер ответ
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip error: %v", err)
		}
		defer gz.Close()
		reader = gz
	} else {
		reader = resp.Body
	}
	// ------------------

	decoder := json.NewDecoder(reader)

	// Читаем открывающую скобку '['
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid json start: %v", err)
	}

	var (
		totalRead     int64 = 0
		totalInserted int64 = 0
	)

	batchSize := 1000
	batch := make([]domain.Threat, 0, batchSize)

	fmt.Println("PhishTank: Начинаю потоковый парсинг...")

	for decoder.More() {
		var item phishTankEntry
		if err := decoder.Decode(&item); err != nil {
			// Если одна строка битая, не падаем, идем дальше
			continue
		}

		totalRead++

		threat := domain.Threat{
			URL:        item.URL,
			Source:     "phishtank",
			ExternalID: strconv.Itoa(item.PhishID),
			Type:       "phishing",
		}
		batch = append(batch, threat)

		if len(batch) >= batchSize {
			inserted, err := s.repo.SaveBatch(ctx, batch)
			if err != nil {
				fmt.Printf("PhishTank DB Error: %v\n", err)
			}
			totalInserted += inserted
			batch = batch[:0]

			if totalRead%5000 == 0 {
				fmt.Printf("PhishTank: Прочитано %d...\n", totalRead)
			}
		}
	}

	if len(batch) > 0 {
		inserted, _ := s.repo.SaveBatch(ctx, batch)
		totalInserted += inserted
	}

	fmt.Printf("=== PhishTank ЗАВЕРШЕН: %d строк, %d новых ===\n", totalRead, totalInserted)
	return nil
}