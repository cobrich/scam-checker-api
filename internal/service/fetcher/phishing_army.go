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

type PhishingArmyService struct {
	repo *repository.ThreatRepository
}

func NewPhishingArmyService(repo *repository.ThreatRepository) *PhishingArmyService {
	return &PhishingArmyService{repo: repo}
}

func (s *PhishingArmyService) Run(ctx context.Context) error {
	url := "https://phishing.army/download/phishing_army_blocklist_extended.txt"
	slog.Info("Starting Phishing Army update", "url", url)

	client := &http.Client{Timeout: 60 * time.Second}
	
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
		return fmt.Errorf("Phishing Army status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var totalInserted int64 = 0
	batch := make([]domain.Threat, 0, 1000)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' { continue }

		threat := domain.Threat{
			URL:        "http://" + line, // Это домены
			Source:     "phishing_army",
			Type:       "phishing",
			ExternalID: "",
		}
		batch = append(batch, threat)

		if len(batch) >= 1000 {
			inserted, _ := s.repo.SaveBatch(ctx, batch)
			totalInserted += inserted
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		inserted, _ := s.repo.SaveBatch(ctx, batch)
		totalInserted += inserted
	}

	slog.Info("Phishing Army finished", "new_threats", totalInserted)
	return nil
}