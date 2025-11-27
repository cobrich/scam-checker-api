package infra

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/pkg/utils"
	"github.com/oschwald/geoip2-golang"
)

var riskyCountries = map[string]int{
	"Russia":      15,
	"China":       15,
	"Iran":        30,
	"North Korea": 50,
	"Brazil":      10,
	"Netherlands": 10,
	"Turkey":      10,

	// Francophone Africa (Common source of scams targeting France)
	"Cote D'Ivoire": 25, // Ivory Coast - очень высокий риск для Франции
	"Benin":         25,
	"Cameroon":      20,
	"Senegal":       15,
	"Mali":          15,

	// Other
	"Nigeria": 20, "Vietnam": 10,
}

var bulletproofHosts = []string{
	"FlokiNET", "Shinjiru", "AbeloHost", "Offshore", "AnonymousSpeech",
	"Njalla", "Privex", "OrangeWebsite", "PrivateLayer", "Virtual Systems",
}

var cloudProviders = []string{
	"DigitalOcean", "Hetzner", "OVH", "Namecheap", "Hostinger",
	"Choopa", "Vultr", "Google LLC", "Amazon.com", "Cloudflare",
}

type InfraService struct {
	geoCity *geoip2.Reader
	geoASN  *geoip2.Reader
}

func NewInfraService(city *geoip2.Reader, asn *geoip2.Reader) *InfraService {
	return &InfraService{geoCity: city, geoASN: asn}
}

// Scan выполняет все сетевые проверки и возвращает результат
func (s *InfraService) Scan(ctx context.Context, rawURL string) (*domain.GeoNetInfo, []domain.RuleMatch, int) {
	domainName, _ := utils.ExtractHostname(rawURL)

	info := &domain.GeoNetInfo{Status: "Offline"}
	var rules []domain.RuleMatch
	score := 0

	// 1. DNS Resolve
	// Используем LookupIP, чтобы проверить, жив ли сайт
	start := time.Now()
	ips, err := net.LookupIP(domainName)
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

	// Проверка страны
	if risk, ok := riskyCountries[info.Geo.Country]; ok {
		score += risk
		rules = append(rules, domain.RuleMatch{Name: "Risky Country", Desc: info.Geo.Country, Score: risk})
	}

	// Проверяем хостинг (возвращает баллы и правила)
	hScore, hRules := s.analyzeHosting(info.Geo)
	score += hScore
	rules = append(rules, hRules...)

	// 3. SSL
	info.SSL = s.getSSLDetails(domainName)

	// Анализируем SSL (возвращает баллы и правила)

	if info.SSL != nil { // <--- ПРОВЕРКА НА NIL
		sslScore, sslRules := s.analyzeSSL(info.SSL)
		score += sslScore
		rules = append(rules, sslRules...)
	} else {
		// Если SSL нет, но сайт жив (HTTP) - это плохо, но не фатально
		score += 5
		rules = append(rules, domain.RuleMatch{Name: "No HTTPS", Desc: "No secure connection", Score: 5})
	}

	// 4. DNS Details (MX)
	info.DNS = s.getDNSDetails(domainName)
	// No MX - это слабый сигнал (многие лендинги не имеют почты)
	if info.DNS == nil || len(info.DNS.MXRecords) == 0 {
		score += 5
		rules = append(rules, domain.RuleMatch{Name: "No MX Records", Desc: "Domain cannot receive emails", Score: 5})
	}

	// 5. HTTP Content Analysis (НОВОЕ)
	// Передаем domainName (или лучше полный URL, если он есть в контексте, но пока domainName)
	httpInfo, httpRules := s.scanHTTP(ctx, rawURL)
	if httpInfo != nil {
		info.HTTP = httpInfo
		rules = append(rules, httpRules...)

		// Если нашли поле пароля на сайте без HTTPS или с плохим доменом - повышаем риск
		if httpInfo.HasPasswordField {
			// Поле пароля на сайте без HTTPS или с плохой репутацией - это риск
			// Но само по себе - нет.
			// Добавим правило, но с малым весом, пусть Analyzer решает
			rules = append(rules, domain.RuleMatch{Name: "Password Field", Desc: "Input type password", Score: 0})
		}
	}

	return info, rules, score
}

// --- Вспомогательные методы ---

func (s *InfraService) getDNSDetails(domainName string) *domain.DNSDetails {
	details := &domain.DNSDetails{}
	found := false

	mxRecords, _ := net.LookupMX(domainName)
	for _, mx := range mxRecords {
		details.MXRecords = append(details.MXRecords, mx.Host)
		found = true
	}

	nsRecords, _ := net.LookupNS(domainName)
	for _, ns := range nsRecords {
		details.NSRecords = append(details.NSRecords, ns.Host)
		found = true
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

	// 1. Bulletproof Hosting
	for _, bp := range bulletproofHosts {
		if strings.Contains(strings.ToLower(geo.ISP), strings.ToLower(bp)) {
			score += 40
			rules = append(rules, domain.RuleMatch{Name: "Bulletproof Hosting", Desc: geo.ISP, Score: 40})
			return score, rules // Если нашли Bulletproof, дальше не проверяем Cloud
		}
	}

	// 2. Cloud Hosting
	// Cloud Hosting - больше НЕ штрафуем (это норма)
	// Оставляем правило с 0 score для информации
	for _, p := range cloudProviders {
		if strings.Contains(geo.ISP, p) {
			// score += 5
			rules = append(rules, domain.RuleMatch{Name: "Cloud Hosting", Desc: geo.ISP, Score: 0})
			break
		}
	}
	return score, rules
}

func (s *InfraService) getSSLDetails(domainName string) *domain.SSLInfo {
	info := &domain.SSLInfo{Valid: false, IsHTTPS: false}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
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
