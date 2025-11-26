package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type OpenPhishService struct {
	repo *repository.ThreatRepository
}

func NewOpenPhishService(repo *repository.ThreatRepository) *OpenPhishService {
	return &OpenPhishService{repo: repo}
}

func (s *OpenPhishService) Run(ctx context.Context) error {
	url := "https://openphish.com/feed.txt"
	fmt.Println("Запуск обновления OpenPhish...")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("OpenPhish API returned status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)

	// Счетчики
	var (
		totalRead     int64 = 0
		totalInserted int64 = 0
	)

	batchSize := 1000
	batch := make([]domain.Threat, 0, batchSize)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		totalRead++

		threat := domain.Threat{
			URL:        line,
			Source:     "openphish",
			Type:       "phishing",
			ExternalID: "", // У них нет ID в бесплатном фиде
		}
		batch = append(batch, threat)

		if len(batch) >= batchSize {
			inserted, err := s.repo.SaveBatch(ctx, batch)
			if err != nil {
				fmt.Printf("OpenPhish DB Error: %v\n", err)
			}
			totalInserted += inserted
			batch = batch[:0]
		}
	}

	// Сохраняем остатки
	if len(batch) > 0 {
		inserted, err := s.repo.SaveBatch(ctx, batch)
		if err == nil {
			totalInserted += inserted
		}
	}

	// Красивый отчет
	fmt.Printf("=== OpenPhish ЗАВЕРШЕН: %d строк, %d новых ===\n", totalRead, totalInserted)

	return nil
}
