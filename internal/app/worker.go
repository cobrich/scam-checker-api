package app

import (
	"context"
	"log/slog"

	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service/fetcher"
	"github.com/robfig/cron/v3"
)

func StartBackgroudJobs(ctx context.Context, repo *repository.ThreatRepository, enable bool) {
	if !enable {
		slog.Info("Background fetchers disabled")
		return
	}

	slog.Info("Starting background fetchers...")

	// fetchers
	phishService := fetcher.NewPhishTankService(repo)
	urlHausService := fetcher.NewUrlHausService(repo)
	openphishService := fetcher.NewOpenPhishService(repo)
	threatfoxService := fetcher.NewThreatFoxService(repo)
	githubPhishService := fetcher.NewGithubPhishingService(repo)
	vxVaultService := fetcher.NewVXVaultService(repo)
	stopSpamService := fetcher.NewStopForumSpamService(repo)
	phishingArmyService := fetcher.NewPhishingArmyService(repo)

	// cron
	c := cron.New()

	// helpers
	runJob := func(name string, job func(context.Context) error) {
		slog.Info("Job started", "name", name)
		if err := job(context.Background()); err != nil {
			slog.Error("Job failed", "name", name, "error", err)
		} else {
			slog.Info("Job finished", "name", name)
		}
	}

	// schedule
	c.AddFunc("@hourly", func() { runJob("PhishTank", phishService.Run) })
	c.AddFunc("@every 30m", func() { runJob("URLhaus", urlHausService.Run) })
	c.AddFunc("@every 12h", func() { runJob("OpenPhish", openphishService.Run) })
	c.AddFunc("@every 1h", func() { runJob("ThreatFox", threatfoxService.Run) })
	c.AddFunc("@every 2h", func() { runJob("GitHub Phishing", githubPhishService.Run) })
	c.AddFunc("@every 1h", func() { runJob("VX Vault", vxVaultService.Run) })
	c.AddFunc("@daily", func() { runJob("StopForumSpam", stopSpamService.Run) })
	c.AddFunc("@every 4h", func() { runJob("Phishing Army", phishingArmyService.Run) })

	c.Start()

	// Initial Run (Async)
	go runJob("PhishTank (Init)", phishService.Run)
	go runJob("URLhaus (Init)", urlHausService.Run)
	go runJob("OpenPhish (Init)", openphishService.Run)
	go runJob("ThreatFox (Init)", threatfoxService.Run)
	go runJob("Github Phishing (Init)", githubPhishService.Run)
	go runJob("VX Vault (Init)", vxVaultService.Run)
	go runJob("StopForumSpam (Init)", stopSpamService.Run)
	go runJob("Phishing Army (Init)", phishingArmyService.Run)
}
