package service

import (
	"context"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service/analyzer"
	"github.com/cobrich/scam-checker-api/internal/service/infra"
)

type CheckerService struct {
	repo      *repository.ThreatRepository
	whitelist *WhitelistService
	infra     *infra.InfraService
}

func NewCheckerService(repo *repository.ThreatRepository, whitelist *WhitelistService, infra *infra.InfraService) *CheckerService {
	return &CheckerService{
		repo:      repo,
		whitelist: whitelist,
		infra:     infra,
	}
}

func (s *CheckerService) Analyze(ctx context.Context, rawURL string, fullScan bool) (*domain.FullReport, error) {
	// Инициализируем базовый отчет
	report := &domain.FullReport{
		Target:    rawURL,
		RiskScore: 0,
	}

	// 1. Whitelist (Мгновенный красивый выход)
	if s.whitelist.IsWhitelisted(rawURL) {
		report.Verdict = "Safe"
		report.Reason = "Whitelisted Domain"
		return report, nil
	}

	// 2. Database check
	threats, err := s.repo.GetThreatsByHash(ctx, utils.HashURL(rawURL))
	if err == nil && len(threats) > 0 {
		report.RiskScore = 100
		report.Verdict = "Dangerous"
		report.Reason = "Found in Blacklist"

		// Проходим по всем найденным записям
		for _, t := range threats {
			report.Blacklists = append(report.Blacklists, domain.BlacklistInfo{
				Source:     t.Source,
				ExternalID: t.ExternalID,
				Type:       t.Type,
				FirstSeen:  t.CreatedAt.Format("2006-01-02"),
			})
		}

		if !fullScan {
			return report, nil
		}
	}

	// 3. Analyzer (Heuristics)
	heuristicRules, heuristicScore := analyzer.Analyze(rawURL)

	// Добавляем их в отчет
	if len(heuristicRules) > 0 {
		report.Heuristics = append(report.Heuristics, heuristicRules...)
		report.RiskScore += heuristicScore
		if report.Reason == "" {
			report.Reason = "Heuristic analyze"
		}
	}

	// 4. Infra (Сетевая проверка)
	domainName, _ := utils.ExtractHostname(rawURL)
	if fullScan && domainName != "" {
		// Вызываем сервис infra
		// infraInfo, infraRules, infraScore := s.infra.Scan(ctx, domainName)
		infraInfo, infraRules, infraScore := s.infra.Scan(ctx, rawURL)

		report.Infrastructure = infraInfo

		// Добавляем правила от инфраструктуры в общий список угроз
		if len(infraRules) > 0 {
			report.Heuristics = append(report.Heuristics, infraRules...)
		}

		if report.RiskScore < 100 {
			report.RiskScore += infraScore
		}
	}

	// 5. Финализация
	if report.RiskScore > 100 {
		report.RiskScore = 100
	}
	// Если вердикт еще не поставлен (например, риск был низким), вычисляем его
	if report.Verdict == "" {
		report.Verdict = calculateVerdict(report.RiskScore)
	}

	// Чистка JSON (чтобы не было null или пустых массивов)
	if len(report.Heuristics) == 0 {
		report.Heuristics = nil
	}
	if len(report.Blacklists) == 0 {
		report.Blacklists = nil
	}

	return report, nil
}

func calculateVerdict(score int) string {
	if score < 20 {
		return "Safe"
	}
	if score < 60 {
		return "Suspicious"
	}
	return "Dangerous"
}
