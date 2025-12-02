package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	slog.Info("Starting ThreatFox...")

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

	var data map[string][]ThreatFoxItem

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		preview := string(bodyBytes)
		if len(preview) > 100 {
			preview = preview[:100]
		}
		return fmt.Errorf("ThreatFox JSON decode error: %v. Body: %s", err, preview)
	}

	batch := make([]domain.Threat, 0, 1000)
	count := 0

	for id, items := range data {
		for _, item := range items {
			if item.IocType != "url" && item.IocType != "domain" {
				continue
			}

			threat := domain.Threat{
				URL:        item.IocValue,
				Source:     "threatfox",
				ExternalID: id,
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

	slog.Info("=== ThreatFox ENDED:",
		"count", count,
	)
	return nil
}
