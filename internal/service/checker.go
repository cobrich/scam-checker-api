package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service/analyzer"
	"github.com/cobrich/scam-checker-api/internal/service/cache"
	"github.com/cobrich/scam-checker-api/internal/service/infra"
	"github.com/cobrich/scam-checker-api/internal/service/whois"
)

type CheckerService struct {
	repo      *repository.ThreatRepository
	whitelist *WhitelistService
	infra     *infra.InfraService
	whois     *whois.WhoisService
	analyzer  *analyzer.Analyzer
	cache     *cache.RedisCache
}

func NewCheckerService(repo *repository.ThreatRepository, whitelist *WhitelistService,
	infra *infra.InfraService, cfg *domain.AppConfig, redisCache *cache.RedisCache) *CheckerService {
	return &CheckerService{
		repo:      repo,
		whitelist: whitelist,
		infra:     infra,
		whois:     whois.NewWhoisService(),
		analyzer:  analyzer.NewAnalyzer(cfg),
		cache:     redisCache,
	}
}

func (s *CheckerService) Analyze(ctx context.Context, rawURL string) (*domain.FullReport, error) {
	// check cache
	cacheKey := fmt.Sprintf("check:%s", utils.HashURL(rawURL))
	if s.cache != nil {
		if cachedReport, err := s.cache.Get(ctx, cacheKey); err == nil && cachedReport != nil {
			// cachedReport.Reason += " (Cached)"
			return cachedReport, nil
		}
	}

	report := &domain.FullReport{
		Target:     rawURL,
		RiskScore:  0,
		Signals:    []string{},
		Heuristics: []domain.RuleMatch{},
	}

	// 1. Whitelist
	if s.whitelist.IsWhitelisted(rawURL) {
		report.Verdict = "Safe"
		report.Reason = "Whitelisted Domain"
		return report, nil
	}

	// 2. Database check
	threats, err := s.repo.GetThreatsByHash(ctx, utils.HashURL(rawURL))
	isBlacklisted := false

	if err == nil && len(threats) > 0 {
		isBlacklisted = true
		report.RiskScore = 100
		report.Verdict = "Dangerous"
		report.Reason = "Found in Blacklist"

		for _, t := range threats {
			report.Blacklists = append(report.Blacklists, domain.BlacklistInfo{
				Source:     t.Source,
				ExternalID: t.ExternalID,
				Type:       t.Type,
				FirstSeen:  t.CreatedAt.Format("2006-01-02"),
			})
			report.Signals = append(report.Signals, fmt.Sprintf("Listed in %s as %s", t.Source, t.Type))
		}
	}

	// 3. Infra Scan
	domainName, _ := utils.ExtractHostname(rawURL)

	meta := &analyzer.AnalyzeMeta{
		IsWhitelisted: false,
		IsBlacklisted: isBlacklisted,
		DomainAgeDays: 0,
		IsTrustedASN:  false,
	}

	if domainName != "" {
		whoisCtx, wCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer wCancel()

		whoisInfo := s.whois.GetInfo(whoisCtx, domainName)
		report.Whois = whoisInfo

		if whoisInfo != nil {
			meta.DomainAgeDays = whoisInfo.DomainAgeDays
		}

		infraCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
		defer cancel()

		infraInfo, infraRules, infraScore := s.infra.Scan(infraCtx, rawURL)
		report.Infrastructure = infraInfo

		if infraInfo.Geo != nil {
			meta.IsTrustedASN = isTrustedASN(infraInfo.Geo.ISP)
		}

		if meta.DomainAgeDays == 0 && infraInfo.SSL != nil {
			meta.DomainAgeDays = infraInfo.SSL.AgeDays
		}

		// 1. If the domain is old (> 1 year), technical flaws (Fresh SSL, No MX) are less important.
		// We reduce the risk from infrastructure by 50%.
		if meta.DomainAgeDays > 365 {
			infraScore = int(float64(infraScore) * 0.5)
		}

		// 2. If the hosting is trusted (Cloudflare, Google), reduce it further.
		if meta.IsTrustedASN {
			infraScore -= 10
		}

		if infraScore < 0 {
			infraScore = 0
		}

		if len(infraRules) > 0 {
			report.Heuristics = append(report.Heuristics, infraRules...)
		}

		if report.RiskScore < 100 {
			report.RiskScore += infraScore
		}
	}

	// 4. Analyzer (Heuristics)
	heuristicScore, heuristicRules := s.analyzer.Analyze(rawURL, meta)

	if len(heuristicRules) > 0 {
		report.Heuristics = append(report.Heuristics, heuristicRules...)

		if report.RiskScore < 100 {
			report.RiskScore += heuristicScore
		}

		if report.Reason == "" {
			report.Reason = "Suspicious Activity Detected"
		}
	}

	// 5. Filaization
	if report.RiskScore > 100 {
		report.RiskScore = 100
	}
	if report.Verdict == "" {
		report.Verdict = calculateVerdict(report.RiskScore)
	}

	s.generateSummary(report)

	if len(report.Heuristics) == 0 {
		report.Heuristics = nil
	}
	if len(report.Blacklists) == 0 {
		report.Blacklists = nil
	}
	if len(report.Signals) == 0 {
		report.Signals = nil
	}

	// save in cache
	if s.cache != nil {
		go func() {
			_ = s.cache.Set(context.Background(), cacheKey, report)
		}()
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

func isTrustedASN(isp string) bool {
	isp = strings.ToLower(isp)
	trusted := []string{"google", "amazon", "cloudflare", "microsoft", "fastly", "akamai"}
	for _, t := range trusted {
		if strings.Contains(isp, t) {
			return true
		}
	}
	return false
}

func (s *CheckerService) generateSummary(report *domain.FullReport) {
	summary := &domain.HeuristicSummary{}

	for _, rule := range report.Heuristics {
		report.Signals = append(report.Signals, rule.Name)

		switch {
		case rule.Score >= 40:
			summary.Critical++
		case rule.Score >= 25:
			summary.High++
		case rule.Score >= 15:
			summary.Medium++
		default:
			summary.Low++
		}
	}

	if summary.Critical+summary.High+summary.Medium+summary.Low > 0 {
		report.Summary = summary
	}
}
