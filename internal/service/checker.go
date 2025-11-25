package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/cobrich/scam-checker-api/internal/repository"
	"github.com/cobrich/scam-checker-api/internal/service/analyzer"
	"github.com/oschwald/geoip2-golang"
)

type CheckerService struct {
	repo      *repository.ThreatRepository
	whitelist *WhitelistService
	geoCityDB *geoip2.Reader
	geoAsnDB  *geoip2.Reader
}

func NewCheckerService(repo *repository.ThreatRepository) *CheckerService {
	cityDB, _ := geoip2.Open("GeoLite2-City.mmdb")
	asnDB, _ := geoip2.Open("GeoLite2-ASN.mmdb")

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
	// Инициализируем базовый отчет
	report := &domain.FullReport{
		Target:    rawURL,
		RiskScore: 0,
		Threats:   &domain.ThreatInfo{}, // Инициализируем, чтобы добавлять эвристику
	}

	// 0. Whitelist (Мгновенный красивый выход)
	if s.whitelist.IsWhitelisted(rawURL) {
		report.Verdict = "Safe"
		report.Reason = "Whitelisted Domain"
		report.Threats = nil // Убираем блок угроз вообще
		return report, nil
	}

	// --- ЭТАП 1: БАЗА ДАННЫХ ---
	threat, err := s.repo.GetThreatByHash(ctx, utils.HashURL(rawURL))
	if err == nil && threat != nil {
		report.RiskScore = 100
		report.Verdict = "Dangerous"
		report.Reason = "Found in Blacklist"

		report.Threats.Blacklist = &domain.BlacklistStatus{
			Source:     threat.Source,
			ExternalID: threat.ExternalID,
			FirstSeen:  threat.CreatedAt.Format("2006-01-02"),
		}

		if !fullScan {
			return report, nil
		}
	}

	// --- ЭТАП 2: ЭВРИСТИКА ---
	stringScore, rules := analyzer.AnalyzeString(rawURL)
	// Преобразуем правила в новый формат (если они отличаются v2, или используем как есть v1)
	report.Threats.Heuristics = append(report.Threats.Heuristics, rules...)
	// for _, r := range rules {
	// 	report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
	// 		Name:  r.Name,
	// 		Desc:  r.Desc,
	// 		Score: r.Score,
	// 	})
	// }

	if report.RiskScore < 100 {
		report.RiskScore += stringScore
	}

	// --- 3. ИНФРАСТРУКТУРА ---
	domainName, _ := utils.ExtractHostname(rawURL)

	// Инициализируем структуру инфраструктуры
	report.Infrastructure = &domain.GeoNetInfo{
		Status: "Offline", // По умолчанию
	}

	if domainName != "" {
		ips, err := net.LookupIP(domainName)

		if err == nil && len(ips) > 0 {
			// САЙТ ЖИВ
			ipStr := ips[0].String()
			report.Infrastructure.Status = "Online"
			report.Infrastructure.IP = ipStr

			// 3.1 GeoIP
			report.Infrastructure.Geo = s.getGeoInfo(ipStr)
			s.evaluateHosting(report.Infrastructure.Geo, report)

			// 3.2 DNS
			report.Infrastructure.DNS = s.getDNSDetails(domainName, report)

			// 3.3 SSL
			report.Infrastructure.SSL = s.getSSLDetails(domainName)
			s.evaluateSSL(report.Infrastructure.SSL, report)
		}
	}

	// Финализация
	if report.RiskScore > 100 {
		report.RiskScore = 100
	}
	if report.Verdict == "" {
		report.Verdict = s.calculateVerdict(report.RiskScore)
	}

	// Если угроз не найдено вообще, делаем поле nil, чтобы оно исчезло из JSON
	if report.Threats.Blacklist == nil && len(report.Threats.Heuristics) == 0 {
		report.Threats = nil
	}

	return report, nil
}

// --- Вспомогательные методы (Refactored) ---

func (s *CheckerService) getDNSDetails(domainName string, report *domain.FullReport) *domain.DNSDetails {
	details := &domain.DNSDetails{}

	mxRecords, _ := net.LookupMX(domainName)
	for _, mx := range mxRecords {
		details.MXRecords = append(details.MXRecords, mx.Host)
	}

	nsRecords, _ := net.LookupNS(domainName)
	for _, ns := range nsRecords {
		details.NSRecords = append(details.NSRecords, ns.Host)
	}

	// Логика штрафа за отсутствие MX
	if len(details.MXRecords) == 0 {
		report.RiskScore += 15
		report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
			Name: "No MX Records", Desc: "Domain cannot receive emails", Score: 15,
		})
	}

	return details
}

func (s *CheckerService) getGeoInfo(ip string) *domain.GeoLocation {
	geo := &domain.GeoLocation{ISP: "Unknown"}
	parsedIP := net.ParseIP(ip)

	if s.geoCityDB != nil {
		if record, err := s.geoCityDB.City(parsedIP); err == nil {
			if len(record.Country.Names) > 0 {
				geo.Country = record.Country.Names["en"]
			}
			if len(record.City.Names) > 0 {
				geo.City = record.City.Names["en"]
			}
		}
	}
	if s.geoAsnDB != nil {
		if record, err := s.geoAsnDB.ASN(parsedIP); err == nil {
			geo.ISP = record.AutonomousSystemOrganization
		}
	}
	return geo
}

func (s *CheckerService) evaluateHosting(geo *domain.GeoLocation, report *domain.FullReport) {
	if geo == nil || geo.ISP == "Unknown" {
		return
	}

	suspiciousProviders := []string{"DigitalOcean", "Hetzner", "OVH", "Namecheap", "Hostinger", "Google LLC", "Amazon.com"}
	isCloud := false
	for _, p := range suspiciousProviders {
		if strings.Contains(geo.ISP, p) {
			isCloud = true
			break
		}
	}

	// Проверяем, были ли подозрительные слова
	hasKeywords := false
	if report.Threats != nil {
		for _, rule := range report.Threats.Heuristics {
			if strings.Contains(rule.Name, "Keyword") {
				hasKeywords = true
				break
			}
		}
	}

	if isCloud && hasKeywords {
		report.RiskScore += 20
		report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
			Name: "Suspicious Hosting", Desc: fmt.Sprintf("Bank keyword on cloud: %s", geo.ISP), Score: 20,
		})
	}
}

func (s *CheckerService) getSSLDetails(domainName string) *domain.SSLInfo {
	info := &domain.SSLInfo{Valid: false, IsHTTPS: false}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domainName+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return info
	} // Вернет IsHTTPS: false
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

func (s *CheckerService) evaluateSSL(ssl *domain.SSLInfo, report *domain.FullReport) {
	if !ssl.IsHTTPS {
		report.RiskScore += 10
		report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
			Name: "No HTTPS", Desc: "No secure connection", Score: 10,
		})
		return
	}
	if !ssl.Valid {
		report.RiskScore += 25
		report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
			Name: "Invalid SSL", Desc: "Expired or invalid", Score: 25,
		})
	}
	if ssl.AgeDays < 1 {
		report.RiskScore += 50
		report.Threats.Heuristics = append(report.Threats.Heuristics, domain.RuleMatch{
			Name: "New SSL", Desc: "Created today", Score: 50,
		})
	}
}

func (s *CheckerService) calculateVerdict(score int) string {
	if score < 20 {
		return "Safe"
	}
	if score < 60 {
		return "Suspicious"
	}
	if score < 80 {
		return "Malicious"
	}
	return "Dangerous"
}
