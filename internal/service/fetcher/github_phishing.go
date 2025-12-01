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

type GithubPhishingService struct {
	repo *repository.ThreatRepository
}

func NewGithubPhishingService(repo *repository.ThreatRepository) *GithubPhishingService {
	return &GithubPhishingService{repo: repo}
}

func (s *GithubPhishingService) Run(ctx context.Context) error {
	url := "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
	slog.Info("Starting Github Phishing update", "url", url)

	client := &http.Client{Timeout: 120 * time.Second}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ScamChecker-Bot/1.0") // Добавили UA

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Github API status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var totalInserted int64 = 0
	batch := make([]domain.Threat, 0, 1000)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		threat := domain.Threat{
			URL:        line,
			Source:     "github_phishing",
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

	slog.Info("=== Github Phishing ЗАВЕРШЕН: новых ===\n",
		"totalInserted", totalInserted,
	)
	return nil
}
