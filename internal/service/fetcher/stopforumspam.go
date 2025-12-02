package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type StopForumSpamService struct {
	repo *repository.ThreatRepository
}

func NewStopForumSpamService(repo *repository.ThreatRepository) *StopForumSpamService {
	return &StopForumSpamService{repo: repo}
}

func (s *StopForumSpamService) Run(ctx context.Context) error {
	url := "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt"
	slog.Info("Starting StopForumSpam...")

	client := &http.Client{Timeout: 300 * time.Second}

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
		return fmt.Errorf("DigitalSide status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var totalInserted int64 = 0
	batch := make([]domain.Threat, 0, 1000)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		url := "http://" + line

		threat := domain.Threat{
			URL:        url,
			Source:     "stopforumspam",
			Type:       "spam",
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

	slog.Info("StopForumSpamService finished", "new_threats", totalInserted)
	return nil
}
