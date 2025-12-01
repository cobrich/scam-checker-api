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

func (s *CheckerService) Analyze(ctx context.Context, rawURL string, fullScan bool) (*domain.FullReport, error) {
	// check cache
	cacheKey := fmt.Sprintf("check:%s", utils.HashURL(rawURL))
	if s.cache != nil {
		if cachedReport, err := s.cache.Get(ctx, cacheKey); err == nil && cachedReport != nil {
			// Добавляем пометку, что ответ из кэша (опционально)
			// cachedReport.Reason += " (Cached)"
			return cachedReport, nil
		}
	}

	// Инициализируем базовый отчет
	report := &domain.FullReport{
		Target:     rawURL,
		RiskScore:  0,
		Signals:    []string{},
		Heuristics: []domain.RuleMatch{},
	}

	// 1. Whitelist (Мгновенный красивый выход)
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

		// Проходим по всем найденным записям
		for _, t := range threats {
			report.Blacklists = append(report.Blacklists, domain.BlacklistInfo{
				Source:     t.Source,
				ExternalID: t.ExternalID,
				Type:       t.Type,
				FirstSeen:  t.CreatedAt.Format("2006-01-02"),
			})
			report.Signals = append(report.Signals, fmt.Sprintf("Listed in %s as %s", t.Source, t.Type))
		}

		// if !fullScan {
		// 	return report, nil
		// }
	}

	// // 3. Analyzer (Heuristics)
	// heuristicRules, heuristicScore := analyzer.Analyze(rawURL)

	// // Добавляем их в отчет
	// if len(heuristicRules) > 0 {
	// 	report.Heuristics = append(report.Heuristics, heuristicRules...)
	// 	report.RiskScore += heuristicScore
	// 	if report.Reason == "" {
	// 		report.Reason = "Heuristic analyze"
	// 	}
	// }

	// 3. Infra Scan (Сначала сеть, чтобы получить данные для анализатора)
	domainName, _ := utils.ExtractHostname(rawURL)

	// Подготовка метаданных для анализатора
	meta := &analyzer.AnalyzeMeta{
		IsWhitelisted: false,
		IsBlacklisted: isBlacklisted,
		DomainAgeDays: 0,
		IsTrustedASN:  false,
	}

	// if fullScan && domainName != ""
	if domainName != "" {
		// Запрашиваем Whois. Это может занять 1-2 секунды.
		whoisCtx, wCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer wCancel()
		whoisInfo := s.whois.GetInfo(whoisCtx, domainName)
		report.Whois = whoisInfo

		if whoisInfo != nil {
			meta.DomainAgeDays = whoisInfo.DomainAgeDays // Передаем в анализатор!
		}

		// Ставим 6 секунд.
		// Если DNS (2с) + HTTP (4с) будут работать последовательно - мы не успеем.
		// Но они работают ПАРАЛЛЕЛЬНО (в scanner.go), поэтому 6 секунд хватит с запасом.
		infraCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
		defer cancel()

		// Вызываем сервис infra
		infraInfo, infraRules, infraScore := s.infra.Scan(infraCtx, rawURL)
		report.Infrastructure = infraInfo

		// Заполняем мету данными из инфраструктуры
		if infraInfo.Geo != nil {
			meta.IsTrustedASN = isTrustedASN(infraInfo.Geo.ISP)
		}
		// Если Whois не сработал, пробуем взять возраст из SSL (как запасной вариант)
		if meta.DomainAgeDays == 0 && infraInfo.SSL != nil {
			meta.DomainAgeDays = infraInfo.SSL.AgeDays
		}

		// --- ЛОГИКА КОРРЕКЦИИ ИНФРАСТРУКТУРЫ (НОВОЕ) ---

		// 1. Если домен старый (> 1 года), технические огрехи (Fresh SSL, No MX) менее важны.
		// Снижаем риск от инфраструктуры на 50%.
		if meta.DomainAgeDays > 365 {
			infraScore = int(float64(infraScore) * 0.5)
		}

		// 2. Если хостинг доверенный (Cloudflare, Google), снижаем еще.
		if meta.IsTrustedASN {
			infraScore -= 10
		}

		// Защита от отрицательных чисел
		if infraScore < 0 {
			infraScore = 0
		}

		// Добавляем правила
		if len(infraRules) > 0 {
			report.Heuristics = append(report.Heuristics, infraRules...)
		}

		// Добавляем скорректированный балл
		if report.RiskScore < 100 {
			report.RiskScore += infraScore
		}
	}

	// 4. Analyzer (Heuristics) - Теперь вызываем в конце с полными данными
	heuristicScore, heuristicRules := s.analyzer.Analyze(rawURL, meta)

	if len(heuristicRules) > 0 {
		report.Heuristics = append(report.Heuristics, heuristicRules...)

		// Добавляем баллы, только если риск еще не 100
		if report.RiskScore < 100 {
			report.RiskScore += heuristicScore
		}

		if report.Reason == "" {
			report.Reason = "Suspicious Activity Detected"
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

	s.generateSummary(report)

	// Чистка JSON (чтобы не было null или пустых массивов)
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
		// Сохраняем в фоне, чтобы не тормозить ответ
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

// Простой список доверенных провайдеров для снижения баллов
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

// generateSummary заполняет Summary и Signals на основе правил
func (s *CheckerService) generateSummary(report *domain.FullReport) {
	summary := &domain.HeuristicSummary{}

	for _, rule := range report.Heuristics {
		// Добавляем имя правила в сигналы
		report.Signals = append(report.Signals, rule.Name)

		// Считаем статистику по баллам
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

	// Если есть хоть какие-то угрозы, добавляем summary
	if summary.Critical+summary.High+summary.Medium+summary.Low > 0 {
		report.Summary = summary
	}
}
