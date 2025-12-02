package fetcher

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"

	"io"
	"net/http"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type UrlHausService struct {
	repo *repository.ThreatRepository
}

func NewUrlHausService(repo *repository.ThreatRepository) *UrlHausService {
	return &UrlHausService{repo: repo}
}

func (s *UrlHausService) Run(ctx context.Context) error {
	url := "https://urlhaus.abuse.ch/downloads/csv_online/"
	slog.Info("Starting URLhaus...")

	client := &http.Client{Timeout: 120 * time.Second} // Файл может быть большим
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)

	reader.Comment = '#'
	reader.FieldsPerRecord = -1

	var (
		totalRead     int64 = 0
		totalInserted int64 = 0
		totalSkipped  int64 = 0
	)

	batchSize := 1000
	batch := make([]domain.Threat, 0, batchSize)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Ошибка CSV строки: %v\n", err)
			continue
		}

		if len(record) < 3 {
			continue
		}

		id := record[0]
		url := record[2]

		totalRead++

		threat := domain.Threat{
			URL:        url,
			Source:     "urlhaus",
			ExternalID: id,
		}
		batch = append(batch, threat)

		if len(batch) >= batchSize {
			inserted, err := s.repo.SaveBatch(ctx, batch)
			if err != nil {
				slog.Error("Error saving: %v\n",
					"error", err,
				)
			}
			totalInserted += inserted
			totalSkipped += (int64(len(batch)) - inserted)
			batch = batch[:0]
		}
	}

	// Остатки
	if len(batch) > 0 {
		inserted, _ := s.repo.SaveBatch(ctx, batch)
		totalInserted += inserted
		totalSkipped += (int64(len(batch)) - inserted)
	}

	slog.Info("=== UrlHaus ENDED:",
		"total_read", totalRead,
		"inserted", totalInserted,
	)

	return nil
}
