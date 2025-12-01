package infra

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/oschwald/geoip2-golang"
)

type InfraService struct {
	geoCity *geoip2.Reader
	geoASN  *geoip2.Reader
	cfg     *domain.AppConfig
}

func NewInfraService(city *geoip2.Reader, asn *geoip2.Reader, cfg *domain.AppConfig) *InfraService {
	return &InfraService{geoCity: city, geoASN: asn, cfg: cfg}
}

// Scan выполняет все сетевые проверки и возвращает результат
func (s *InfraService) Scan(ctx context.Context, rawURL string) (*domain.GeoNetInfo, []domain.RuleMatch, int) {
	domainName, _ := utils.ExtractHostname(rawURL)

	info := &domain.GeoNetInfo{Status: "Offline"}
	var rules []domain.RuleMatch
	score := 0

	// Мьютекс для безопасной записи в rules и score из разных горутин
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 1. DNS Resolve
	// Используем LookupIP, чтобы проверить, жив ли сайт
	// Создаем отдельный контекст для DNS. Максимум 2 секунды.
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer dnsCancel()

	start := time.Now()
	ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", domainName)
	resolveTime := time.Since(start)

	if err != nil || len(ips) == 0 {
		return info, rules, score // Сайт мертв
	}

	// Сайт жив
	info.Status = "Online"
	info.IP = ips[0].String()

	if resolveTime > 500*time.Millisecond {
		rules = append(rules, domain.RuleMatch{Name: "Slow DNS", Desc: "Resolve time > 500ms", Score: 5})
	}

	// 2. GeoIP & Hosting
	info.Geo = s.getGeoInfo(info.IP)

	// Проверка страны (Используем s.cfg.GeoRisks)
	if val, ok := s.cfg.GeoRisks[info.Geo.Country]; ok {
		score += val
		rules = append(rules, domain.RuleMatch{Name: "Risky Country", Desc: info.Geo.Country, Score: val})
	}

	// Проверяем хостинг (возвращает баллы и правила)
	hScore, hRules := s.analyzeHosting(info.Geo)
	score += hScore
	rules = append(rules, hRules...)

	// 3. SSL
	// Task A: SSL Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssl := s.getSSLDetails(domainName)

		mu.Lock()
		defer mu.Unlock()

		info.SSL = ssl
		if ssl != nil {
			sScore, sRules := s.analyzeSSL(ssl)
			score += sScore
			rules = append(rules, sRules...)
		} else {
			score += 5
			rules = append(rules, domain.RuleMatch{Name: "No HTTPS", Desc: "No secure connection", Score: 5})
		}
	}()

	// 4. DNS Details (MX)
	// Task B: DNS Details (MX/NS)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Передаем контекст для таймаута!
		dns := s.getDNSDetails(dnsCtx, domainName)

		mu.Lock()
		defer mu.Unlock()

		info.DNS = dns
		if dns == nil || len(dns.MXRecords) == 0 {
			score += 5
			rules = append(rules, domain.RuleMatch{Name: "No MX Records", Desc: "Domain cannot receive emails", Score: 5})
		}
	}()

	// 5. HTTP Content Analysis (НОВОЕ)
	// Task C: HTTP Scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		httpInfo, httpRules := s.scanHTTP(ctx, rawURL)

		mu.Lock()
		defer mu.Unlock()

		if httpInfo != nil {
			info.HTTP = httpInfo
			rules = append(rules, httpRules...)
		}
	}()

	// Ждем всех
	wg.Wait()

	return info, rules, score
}

// --- Вспомогательные методы ---

func (s *InfraService) getDNSDetails(ctx context.Context, domainName string) *domain.DNSDetails {
	details := &domain.DNSDetails{}
	found := false

	// Используем Resolver с контекстом, чтобы не зависать на MX
	resolver := net.DefaultResolver

	// MX
	if mxs, err := resolver.LookupMX(ctx, domainName); err == nil {
		for _, mx := range mxs {
			details.MXRecords = append(details.MXRecords, mx.Host)
			found = true
		}
	}

	// NS
	if nss, err := resolver.LookupNS(ctx, domainName); err == nil {
		for _, ns := range nss {
			details.NSRecords = append(details.NSRecords, ns.Host)
			found = true
		}
	}
	if !found {
		return nil
	}

	return details
}

func (s *InfraService) getGeoInfo(ip string) *domain.GeoLocation {
	geo := &domain.GeoLocation{ISP: "Unknown"}
	parsedIP := net.ParseIP(ip)

	if s.geoCity != nil {
		if record, err := s.geoCity.City(parsedIP); err == nil {
			if len(record.Country.Names) > 0 {
				geo.Country = record.Country.Names["en"]
			}
			if len(record.City.Names) > 0 {
				geo.City = record.City.Names["en"]
			}
		}
	}
	if s.geoASN != nil {
		if record, err := s.geoASN.ASN(parsedIP); err == nil {
			geo.ISP = record.AutonomousSystemOrganization
			geo.Org = record.AutonomousSystemOrganization // Часто совпадает, но пусть будет
			geo.ASN = int(record.AutonomousSystemNumber)
		}
	}
	return geo
}

// analyzeHosting проверяет, не используется ли подозрительный хостинг
func (s *InfraService) analyzeHosting(geo *domain.GeoLocation) (int, []domain.RuleMatch) {
	score := 0
	var rules []domain.RuleMatch

	if geo == nil || geo.ISP == "Unknown" {
		return 0, nil
	}

	ispLower := strings.ToLower(geo.ISP)

	// Проходим по списку из БД
	for _, hostRule := range s.cfg.Hosting {
		if strings.Contains(ispLower, strings.ToLower(hostRule.Pattern)) {
			// Если это Bulletproof - штрафуем сильно
			if hostRule.Type == "bulletproof" {
				score += hostRule.Score
				rules = append(rules, domain.RuleMatch{
					Name:  "Bulletproof Hosting",
					Desc:  geo.ISP,
					Score: hostRule.Score,
				})
				return score, rules // Нашли худшее, выходим
			}

			// Если Cloud - просто информируем (score может быть 0 или 5)
			if hostRule.Type == "cloud" {
				rules = append(rules, domain.RuleMatch{
					Name:  "Cloud Hosting",
					Desc:  geo.ISP,
					Score: hostRule.Score,
				})
				// Не выходим, вдруг там еще что-то
				break
			}
		}
	}
	return score, rules
}

func (s *InfraService) getSSLDetails(domainName string) *domain.SSLInfo {
	info := &domain.SSLInfo{Valid: false, IsHTTPS: false}

	dialer := &net.Dialer{Timeout: 1 * time.Second}
	// InsecureSkipVerify: true, потому что нам важно получить инфу о сертификате, даже если он просрочен
	conn, err := tls.DialWithDialer(dialer, "tcp", domainName+":443", &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		return nil
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

// analyzeSSL оценивает сертификат
func (s *InfraService) analyzeSSL(ssl *domain.SSLInfo) (int, []domain.RuleMatch) {
	score := 0
	var rules []domain.RuleMatch

	if !ssl.IsHTTPS {
		score += 5
		rules = append(rules, domain.RuleMatch{Name: "No HTTPS", Desc: "No secure connection", Score: 5})
		return score, rules
	}

	if !ssl.Valid {
		score += 25
		rules = append(rules, domain.RuleMatch{Name: "Invalid SSL", Desc: "Expired or invalid", Score: 25})
	}

	if ssl.AgeDays < 1 {
		score += 30
		rules = append(rules, domain.RuleMatch{Name: "New SSL", Desc: "Created today (<24h)", Score: 30})
	} else if ssl.AgeDays < 2 {
		score += 10
		rules = append(rules, domain.RuleMatch{Name: "Fresh SSL", Desc: "Created recently", Score: 10})
	} else if ssl.AgeDays < 7 {
		score += 5
		rules = append(rules, domain.RuleMatch{Name: "Fresh SSL", Desc: "Created this week", Score: 5})
	}

	// Проверка на бесплатные сертификаты на новых доменах
	isFreeCert := strings.Contains(ssl.Issuer, "Let's Encrypt") || strings.Contains(ssl.Issuer, "ZeroSSL") // || strings.Contains(ssl.Issuer, "Google Trust Services")
	if isFreeCert && ssl.AgeDays < 14 {
		score += 5
		rules = append(rules, domain.RuleMatch{Name: "Free SSL on New Site", Desc: "Short-lived free cert", Score: 5})
	}

	return score, rules
}
