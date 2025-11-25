package analyzer

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/cobrich/scam-checker-api/internal/domain"
)

var ipRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// analyzeString анализирует текст ссылки на подозрительные признаки
func AnalyzeString(rawURL string) (int, []domain.RuleMatch) {
	score := 0
	var rules []domain.RuleMatch

	// 1. Парсинг URL
	// Если URL кривой, мы не можем его анализировать
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil
	}

	hostname := strings.ToLower(u.Hostname())
	path := strings.ToLower(u.Path)

	// --- ПРАВИЛО 1: Подозрительные ключевые слова (Keywords) ---
	// Слова, которые часто используют мошенники
	suspiciousKeywords := map[string]int{
		"login":   20,
		"secure":  20,
		"account": 15,
		"update":  15,
		"verify":  20,
		"bank":    25,
		"wallet":  25,
		"confirm": 15,
		"support": 10,
		"service": 10,
		"auth":    15,
		"crypto":  20,
		"binance": 30,
		"paypal":  30,
		"sber":    30,
	}

	for word, impact := range suspiciousKeywords {
		// Ищем слово в домене (очень опасно) или в пути (менее опасно)
		if strings.Contains(hostname, word) {
			score += impact
			rules = append(rules, domain.RuleMatch{
				RuleName:    "Suspicious Keyword in Domain",
				Description: "Domain contains keyword: " + word,
				ScoreImpact: impact,
			})
		} else if strings.Contains(path, word) {
			// В пути вес меньше (например example.com/login - это может быть норм)
			pathImpact := impact / 2
			score += pathImpact
			rules = append(rules, domain.RuleMatch{
				RuleName:    "Suspicious Keyword in Path",
				Description: "URL path contains keyword: " + word,
				ScoreImpact: pathImpact,
			})
		}
	}

	// --- ПРАВИЛО 2: Длинный домен (Long Domain) ---
	// Фишеры любят длинные имена: sberbank-online-secure-login-update.com
	if len(hostname) > 30 {
		impact := 15
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "Long Domain Name",
			Description: "Domain length is greater than 30 characters",
			ScoreImpact: impact,
		})
	}

	// --- ПРАВИЛО 3: Много дефисов (Multiple Hyphens) ---
	// Легитимные сайты редко используют больше 1-2 дефисов
	hyphenCount := strings.Count(hostname, "-")
	if hyphenCount >= 3 {
		impact := 10 * (hyphenCount - 1) // Чем больше, тем хуже
		if impact > 40 {
			impact = 40
		} // Лимит
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "Multiple Hyphens",
			Description: "Domain contains multiple hyphens",
			ScoreImpact: impact,
		})
	}

	// --- ПРАВИЛО 4: Много цифр (High Digit Count) ---
	// Пример: facebook12345.com
	digitCount := 0
	for _, r := range hostname {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}
	if digitCount >= 4 {
		impact := 15
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "Numeric Characters",
			Description: "Domain contains many numeric characters",
			ScoreImpact: impact,
		})
	}

	// --- ПРАВИЛО 5: IP-адрес вместо домена (IP Hostname) ---
	// Пример: http://192.168.1.1/login
	if isIPAddress(hostname) {
		impact := 25
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "IP Address Hostname",
			Description: "URL uses IP address instead of domain name",
			ScoreImpact: impact,
		})
	}

	// --- ПРАВИЛО 6: Подозрительная TLD (Top Level Domain) ---
	// Дешевые или бесплатные доменные зоны
	suspiciousTLDs := []string{".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".ga", ".buzz", ".cn"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(hostname, tld) {
			impact := 10
			score += impact
			rules = append(rules, domain.RuleMatch{
				RuleName:    "Suspicious TLD",
				Description: "Domain uses suspicious TLD: " + tld,
				ScoreImpact: impact,
			})
			break
		}
	}

	// --- ПРАВИЛО 7: @ в URL (Basic Auth trick) ---
	// Пример: http://google.com@evil.com (браузер перейдет на evil.com)
	if strings.Contains(rawURL, "@") {
		impact := 50
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "Obfuscated URL (@ symbol)",
			Description: "URL contains @ symbol, possibly to trick user",
			ScoreImpact: impact,
		})
	}

	// --- ПРАВИЛО 8: Много поддоменов ---
	// Пример: secure.login.update.sber.com (4 точки)
	dotsCount := strings.Count(hostname, ".")
	if dotsCount > 3 && !isIPAddress(hostname) {
		impact := 15
		score += impact
		rules = append(rules, domain.RuleMatch{
			RuleName:    "Many Subdomains",
			Description: "Domain has deep subdomain structure",
			ScoreImpact: impact,
		})
	}

	return score, rules
}

// Вспомогательная функция для проверки IP
func isIPAddress(host string) bool {
	// Простая регулярка для IPv4
	return ipRegex.MatchString(host)
}
