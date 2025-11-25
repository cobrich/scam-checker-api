package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service/analyzer"
	"github.com/cobrich/scam-checker-api/pkg/utils"
	"github.com/oschwald/geoip2-golang"
)

type CheckerService struct {
	repo      *repository.ThreatRepository
	whitelist *WhitelistService // Храним сервис белого списка как поле
	geoCityDB *geoip2.Reader
	geoAsnDB  *geoip2.Reader
}

func NewCheckerService(repo *repository.ThreatRepository) *CheckerService {
	// 1. Открываем City базу
	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		fmt.Println("Warning: GeoLite2-City.mmdb not found")
	}

	// 2. Открываем ASN базу
	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Println("Warning: GeoLite2-ASN.mmdb not found")
	}

	return &CheckerService{
		repo:      repo,
		whitelist: NewWhitelistService(),
		geoCityDB: cityDB,
		geoAsnDB:  asnDB,
	}
}

func (s *CheckerService) Close() {
	if s.geoCityDB != nil {
		s.geoCityDB.Close()
	}
	if s.geoAsnDB != nil {
		s.geoAsnDB.Close()
	}
}

func (s *CheckerService) Analyze(ctx context.Context, rawURL string, fullScan bool) (*domain.FullReport, error) {
	report := &domain.FullReport{
		Target:    rawURL,
		RiskScore: 0,
	}

	// 0. Белый список (теперь быстро)
	if s.whitelist.IsWhitelisted(rawURL) {
		report.Verdict = "Safe (Whitelisted)"
		report.TechnicalFacts.IsReachable = true
		return report, nil
	}

	// --- ЭТАП 1: БАЗА ДАННЫХ ---
	threat, err := s.repo.GetThreatByHash(ctx, utils.HashURL(rawURL))
	if err == nil && threat != nil {
		report.RiskScore = 100
		report.Verdict = "Dangerous"
		report.ThreatDetection.BlacklistStatus = domain.BlacklistStatus{
			IsListed:   true,
			Source:     threat.Source,
			ExternalID: threat.ExternalID,
			FirstSeen:  threat.CreatedAt.String(),
		}
		if !fullScan {
			return report, nil
		}
	}

	// --- ЭТАП 2: ЭВРИСТИКА ---
	stringScore, rules := analyzer.AnalyzeString(rawURL)
	report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, rules...)

	if report.RiskScore < 100 {
		report.RiskScore += stringScore
	}

	// --- 3. ИНФРАСТРУКТУРА (DNS Check First!) ---
	domainName, err := utils.ExtractHostname(rawURL)
	if err != nil {
		// Обработка ошибки, если URL совсем кривой
		domainName = ""
	}

	if domainName != "" {
		// ШАГ 3.1: Пытаемся резолвить DNS (Главный фильтр)
		ips, err := net.LookupIP(domainName)

		if err != nil || len(ips) == 0 {
			// САЙТ МЕРТВ.
			// Мы НЕ проверяем SSL и Geo, так как это бессмысленно.
			// Мы НЕ штрафуем за "No HTTPS", так как сайта нет.
			report.TechnicalFacts.IsReachable = false
		} else {
			// САЙТ ЖИВ.
			report.TechnicalFacts.IsReachable = true
			report.TechnicalFacts.IP = ips[0].String()

			// 3.2 DNS Детали (MX, NS)
			s.enrichDNS(domainName, report)

			// 3.3 GeoIP + ASN
			geoInfo := s.checkGeoAndASN(report.TechnicalFacts.IP)
			report.TechnicalFacts.ServerLocation = &geoInfo

			// Оцениваем хостинг
			s.evaluateHosting(geoInfo, report)

			// 3.4 SSL (Только если сайт жив)
			sslInfo := s.checkSSL(domainName)
			report.TechnicalFacts.SSL = &sslInfo
			s.evaluateSSL(sslInfo, report)
		}
	}
	if report.RiskScore > 100 {
		report.RiskScore = 100
	}
	report.Verdict = s.calculateVerdict(report.RiskScore)

	return report, nil
}

// enrichDNS собирает MX и NS записи
func (s *CheckerService) enrichDNS(domainName string, report *domain.FullReport) {
	// MX
	mxRecords, _ := net.LookupMX(domainName)
	if len(mxRecords) > 0 {
		report.TechnicalFacts.DNS.HasMX = true
		for _, mx := range mxRecords {
			report.TechnicalFacts.DNS.MX = append(report.TechnicalFacts.DNS.MX, mx.Host)
		}
	} else {
		report.TechnicalFacts.DNS.HasMX = false
		// Штрафуем за отсутствие почты только если сайт жив
		report.RiskScore += 15
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "No MX Records", Description: "Domain cannot receive emails", ScoreImpact: 15,
		})
	}

	// NS (Name Servers) - очень полезно!
	nsRecords, _ := net.LookupNS(domainName)
	for _, ns := range nsRecords {
		report.TechnicalFacts.DNS.NS = append(report.TechnicalFacts.DNS.NS, ns.Host)
	}
}

// Вынес логику оценки SSL в отдельный метод для чистоты
func (s *CheckerService) evaluateSSL(sslInfo domain.SSLInfo, report *domain.FullReport) {
	if !sslInfo.IsHTTPS {
		report.RiskScore += 10
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "No HTTPS", Description: "Site does not use secure connection", ScoreImpact: 10,
		})
		return
	}

	// Добавляем проверку валидности
	if !sslInfo.Valid {
		report.RiskScore += 25
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "Invalid SSL", Description: "SSL Certificate is expired or invalid", ScoreImpact: 25,
		})
	}

	if sslInfo.AgeDays < 1 {
		report.RiskScore += 50
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "New SSL Certificate", Description: "Certificate was created today (< 24h)", ScoreImpact: 50,
		})
	} else if sslInfo.AgeDays < 7 {
		report.RiskScore += 20
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "Fresh SSL Certificate", Description: "Certificate is less than 1 week old", ScoreImpact: 20,
		})
	}

	isFreeCert := strings.Contains(sslInfo.Issuer, "Let's Encrypt") || strings.Contains(sslInfo.Issuer, "ZeroSSL")
	if isFreeCert && sslInfo.AgeDays < 14 {
		report.RiskScore += 10
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName: "Free SSL on New Site", Description: "Short-lived free certificate on a new site", ScoreImpact: 10,
		})
	}
}

// checkGeoAndASN теперь достает и Город, и Провайдера
func (s *CheckerService) checkGeoAndASN(ip string) domain.GeoInfo {
	info := domain.GeoInfo{IP: ip, ISP: "Unknown"}
	parsedIP := net.ParseIP(ip)

	// 1. Город
	if s.geoCityDB != nil {
		if record, err := s.geoCityDB.City(parsedIP); err == nil {
			if len(record.Country.Names) > 0 {
				info.Country = record.Country.Names["en"]
			}
			if len(record.City.Names) > 0 {
				info.City = record.City.Names["en"]
			}
		}
	}

	// 2. ASN (Провайдер)
	if s.geoAsnDB != nil {
		if record, err := s.geoAsnDB.ASN(parsedIP); err == nil {
			// AutonomousSystemOrganization - это название компании (напр. "Google LLC", "DigitalOcean, LLC")
			info.ISP = record.AutonomousSystemOrganization
		}
	}

	return info
}

// evaluateHosting проверяет, не используется ли дешевый хостинг для фишинга
func (s *CheckerService) evaluateHosting(geo domain.GeoInfo, report *domain.FullReport) {
	if geo.ISP == "" || geo.ISP == "Unknown" {
		return
	}

	// Список популярных облачных хостингов, которые любят фишеры
	// Само по себе использование Cloudflare или DO - это нормально.
	// Но если RiskScore уже высокий (есть подозрительные слова), то это усугубляет вину.
	suspiciousCloudProviders := []string{
		"DigitalOcean",
		"Hetzner",
		"OVH",
		"Choopa", // Vultr
		"Namecheap",
		"Hostinger",
		"Amazon.com", // AWS часто используют, но банки там редко хостят основной домен
		"Google LLC", // Google Cloud
	}

	isCloud := false
	for _, provider := range suspiciousCloudProviders {
		if strings.Contains(geo.ISP, provider) {
			isCloud = true
			break
		}
	}

	// ЛОГИКА:
	// Если мы уже нашли подозрительные слова (например "sber", "secure")
	// И при этом сайт хостится на DigitalOcean (а не в AS Сбербанка)
	// То это почти гарантированный скам.
	hasSuspiciousKeywords := false
	for _, rule := range report.ThreatDetection.HeuristicRules {
		if rule.RuleName == "Suspicious Keyword in Domain" {
			hasSuspiciousKeywords = true
			break
		}
	}

	if isCloud && hasSuspiciousKeywords {
		report.RiskScore += 20
		report.ThreatDetection.HeuristicRules = append(report.ThreatDetection.HeuristicRules, domain.RuleMatch{
			RuleName:    "Suspicious Hosting",
			Description: fmt.Sprintf("Banking/Security keyword found, but hosted on cloud provider: %s", geo.ISP),
			ScoreImpact: 20,
		})
	}
}

func (s *CheckerService) checkSSL(domainName string) domain.SSLInfo {
	info := domain.SSLInfo{Valid: false, IsHTTPS: false}
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", domainName+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return info
	}
	defer conn.Close()

	info.IsHTTPS = true
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return info
	}
	cert := certs[0]

	info.Issuer = cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 {
		info.Issuer = cert.Issuer.Organization[0]
	}

	now := time.Now()
	if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
		info.Valid = true
	}
	info.AgeDays = int(time.Since(cert.NotBefore).Hours() / 24)
	info.ExpiresIn = int(time.Until(cert.NotAfter).Hours() / 24)

	return info
}

func (s *CheckerService) calculateVerdict(RiskScore int) string {
	if RiskScore < 20 {
		return "Safe"
	} else if RiskScore < 60 {
		return "Suspicious"
	} else if RiskScore < 80 {
		return "Malicious"
	}
	return "Dangerous"
}
