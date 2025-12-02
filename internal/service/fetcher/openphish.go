package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
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
	slog.Info("Starting OpenPhish...")

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
			ExternalID: "",
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

	if len(batch) > 0 {
		inserted, err := s.repo.SaveBatch(ctx, batch)
		if err == nil {
			totalInserted += inserted
		}
	}

	slog.Info("=== OpenPhish ENDED:",
		"total_read", totalRead,
		"inserted", totalInserted,
	)

	return nil
}
