package analyzer

import (
	"encoding/base64"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/agnivade/levenshtein"
	"github.com/cobrich/scam-checker-api/internal/domain"
)

// Регулярки оставляем глобальными (они не меняются)
var (
	ipRegex            = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	unicodeConfusables = regexp.MustCompile(`[^\x00-\x7F]`)
	hexLike            = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	base64Like         = regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
)

// Категории риска
type category string

const (
	Critical category = "critical"
	High     category = "high"
	Medium   category = "medium"
	Low      category = "low"
)

// AnalyzeMeta — метаданные для умного анализа
type AnalyzeMeta struct {
	IsWhitelisted bool
	IsBlacklisted bool
	DomainAgeDays int
	IsTrustedASN  bool
}

// Analyzer - теперь это структура, хранящая конфиг
type Analyzer struct {
	cfg *domain.AppConfig
}

// NewAnalyzer создает инстанс анализатора с загруженным конфигом
func NewAnalyzer(cfg *domain.AppConfig) *Analyzer {
	return &Analyzer{cfg: cfg}
}

func (a *Analyzer) Analyze(rawURL string, meta *AnalyzeMeta) (int, []domain.RuleMatch) {
	// 0. Whitelist Check
	if meta != nil && meta.IsWhitelisted {
		return 0, nil
	}

	var rules []domain.RuleMatch

	// Парсинг
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		u2, err2 := url.Parse("http://" + rawURL)
		if err2 != nil {
			return 0, nil
		}
		u = u2
	}

	hostname := strings.ToLower(u.Hostname())
	cleanHost := strings.TrimPrefix(hostname, "www.")
	tokens := strings.FieldsFunc(cleanHost, func(r rune) bool { return r == '.' || r == '-' })
	path := u.Path
	query := u.RawQuery

	// === ГЕНЕРАЦИЯ ПРАВИЛ ===

	// 1. Protocol (Static)
	if u.Scheme != "https" {
		rules = append(rules, rule("Insecure Protocol", "Non-HTTPS scheme", 10))
	}

	// 2. Unicode (Static)
	if unicodeConfusables.MatchString(hostname) {
		rules = append(rules, rule("Unicode Spoof", "Domain contains confusable chars", 60))
	}

	// 3. Keywords (DYNAMIC FROM DB)
	for _, t := range tokens {
		// Берем балл прямо из конфига
		if val, ok := a.cfg.Keywords[t]; ok {
			rules = append(rules, rule("Suspicious Keyword in Domain", "Keyword '"+t+"'", val))
		}
	}
	pathLower := strings.ToLower(path)
	for kw, val := range a.cfg.Keywords {
		if strings.Contains(pathLower, kw) {
			// В пути вес чуть меньше, но базируется на значении из БД
			pathVal := val
			if pathVal > 15 {
				pathVal = 15
			}
			rules = append(rules, rule("Suspicious Keyword in Path", "Keyword '"+kw+"'", pathVal))
		}
	}

	// 4. Brands (DYNAMIC FROM DB)
	for _, token := range tokens {
		if len(token) < 4 {
			continue
		}
		// Итерируемся по брендам из БД
		for _, brand := range a.cfg.Brands {
			if token == brand {
				continue
			}
			dist := levenshtein.ComputeDistance(token, brand)
			if dist == 1 || (len(brand) >= 6 && dist <= 2) {
				// Тайпосквоттинг - это серьезно, даем высокий балл (можно вынести в настройки, но пока константа)
				rules = append(rules, rule("Typosquatting", "Token '"+token+"' ~ '"+brand+"'", 55))
			}
		}
	}

	// 5. Brand Injection (DYNAMIC FROM DB)
	for _, brand := range a.cfg.Brands {
		if strings.Contains(cleanHost, brand+"-") || strings.Contains(cleanHost, "-"+brand) {
			rules = append(rules, rule("Brand Injection", "Brand '"+brand+"' injected", 40))
		}
	}

	// 6. Fake Parent (DYNAMIC FROM DB)
	for _, brand := range a.cfg.Brands {
		brandDot := brand + "."
		if strings.Contains(cleanHost, brandDot) {
			if strings.HasPrefix(cleanHost, brandDot) {
				rest := strings.TrimPrefix(cleanHost, brandDot)
				if !strings.Contains(rest, ".") {
					continue
				}
			}
			rules = append(rules, rule("Fake Parent Domain", "Subdomain uses '"+brand+"'", 65))
		}
	}

	// 7. Punycode (Static)
	if strings.Contains(hostname, "xn--") {
		rules = append(rules, rule("Punycode", "IDN detected", 50))
	}

	// 8. Entropy (Static)
	if calculateEntropy(cleanHost) > 4.2 {
		rules = append(rules, rule("High Entropy Domain", "Random chars", 10))
	}
	for _, tok := range tokens {
		if len(tok) > 5 && calculateEntropy(tok) > 3.8 {
			rules = append(rules, rule("High Entropy Token", "Token '"+tok+"' looks random", 15))
		}
	}

	// 9. Length (Static)
	if len(cleanHost) > 50 {
		rules = append(rules, rule("Long Domain", "Length > 50", 10))
	}
	for _, tok := range tokens {
		if len(tok) > 25 {
			rules = append(rules, rule("Oversized Token", "Token > 25 chars", 15))
		}
	}

	// 10. Hyphens / Subdomains (Static)
	if strings.Count(cleanHost, "-") >= 4 {
		rules = append(rules, rule("Excessive Hyphens", "4+ hyphens", 10))
	}
	if strings.Count(hostname, ".") >= 4 && !isIPAddress(hostname) {
		rules = append(rules, rule("Deep Subdomain", "4+ levels", 15))
	}

	// 12. IP Hostname (Static)
	if isIPAddress(hostname) {
		rules = append(rules, rule("IP Hostname", "Direct IP access", 40))
	}

	// 13. TLD (DYNAMIC FROM DB)
	tld := getTLD(hostname)
	if val, ok := a.cfg.TLDs[tld]; ok {
		rules = append(rules, rule("Suspicious TLD", "Risky TLD: ."+tld, val))
	}

	// 14. Userinfo (Static)
	if u.User != nil {
		rules = append(rules, rule("Userinfo Abuse", "URL contains userinfo", 50))
	}

	// 15. Port (Static)
	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" {
		rules = append(rules, rule("Suspicious Port", "Port: "+u.Port(), 25))
	}

	// 16. Obfuscation (Static)
	pathTrim := strings.Trim(path, "/")
	if base64Like.MatchString(pathTrim) {
		if decoded, err := base64.StdEncoding.DecodeString(pathTrim); err == nil && isPrintable(decoded) {
			rules = append(rules, rule("Encoded Payload", "Base64 path", 25))
		}
	}
	if hexLike.MatchString(pathTrim) {
		rules = append(rules, rule("Hex Payload", "Hex path", 15))
	}

	// 17. Query (Static)
	if strings.Contains(query, "redirect=") || strings.Contains(query, "next=") || strings.Contains(query, "url=") {
		rules = append(rules, rule("Open Redirect", "Redirect param", 25))
	}
	if strings.Contains(query, "token=") || strings.Contains(query, "session=") || strings.Contains(query, "aff_id=") {
		rules = append(rules, rule("Sensitive Query Parameter", "Session/Token param", 15))
	}

	// 18. @ Symbol (Static)
	if strings.Contains(rawURL, "@") && u.User == nil {
		rules = append(rules, rule("Obfuscated URL", "Contains @", 25))
	}

	// 19. Shorteners (DYNAMIC FROM DB)
	if val, ok := a.cfg.Shorteners[cleanHost]; ok {
		rules = append(rules, rule("URL Shortener", "Short URL", val))
	}

	// 20. IPFS/Workers (Static)
	if strings.Contains(rawURL, "ipfs://") || strings.Contains(hostname, "ipfs") {
		rules = append(rules, rule("IPFS Hosting", "Decentralized storage", 35))
	}
	if strings.HasSuffix(hostname, ".workers.dev") || strings.HasSuffix(hostname, ".pages.dev") {
		rules = append(rules, rule("Cloud Worker", "Cloud worker", 25))
	}

	// 21. New Domain (Meta)
	if meta != nil && meta.DomainAgeDays > 0 && meta.DomainAgeDays <= 14 {
		rules = append(rules, rule("Newly Registered Domain", "Domain < 2 weeks old", 40))
	}

	// === SCORING LOGIC (DYNAMIC CATEGORIZATION) ===

	categorySums := map[category]int{Critical: 0, High: 0, Medium: 0, Low: 0}

	// Пробегаем по всем найденным правилам
	for i := range rules {
		r := &rules[i]

		// Определяем категорию ДИНАМИЧЕСКИ на основе балла
		// Это позволяет менять вес в БД, и категория изменится сама
		if r.Score >= 40 {
			categorySums[Critical] += r.Score
		} else if r.Score >= 25 {
			categorySums[High] += r.Score
		} else if r.Score >= 15 {
			categorySums[Medium] += r.Score
		} else {
			categorySums[Low] += r.Score
		}
	}

	// --- Anti-False Positives ---

	// 1. Trusted ASN
	if meta != nil && meta.IsTrustedASN {
		if categorySums[High] > 10 {
			categorySums[High] -= 10
		} else {
			categorySums[High] = 0
		}
	}

	// 2. Old Domain (> 1 year)
	if meta != nil && meta.DomainAgeDays > 365 {
		categorySums[Medium] = int(float64(categorySums[Medium]) * 0.6)
		categorySums[Low] = int(float64(categorySums[Low]) * 0.5)
	}

	// --- Multipliers ---
	multiplier := 1.0
	if categorySums[Critical] >= 50 {
		multiplier += 0.20
	}
	if categorySums[Critical] >= 100 {
		multiplier += 0.30
	}

	// Комбо: Typosquatting + Punycode (ищем по именам, так как имена статичны)
	hasTypos := false
	hasPuny := false
	for _, r := range rules {
		if r.Name == "Typosquatting" {
			hasTypos = true
		}
		if r.Name == "Punycode" {
			hasPuny = true
		}
	}
	if hasTypos && hasPuny {
		multiplier += 0.25
	}

	// --- Final Calculation (Aggressive) ---
	raw := float64(categorySums[Critical])*1.5 +
		float64(categorySums[High])*1.0 +
		float64(categorySums[Medium])*0.8 +
		float64(categorySums[Low])*0.5

	raw = raw * multiplier
	score := int(raw)

	// Final Anti-FP check
	if meta != nil && meta.DomainAgeDays > 365 && categorySums[Critical] == 0 && categorySums[High] == 0 {
		score = int(float64(score) * 0.4)
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	// Сортировка
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Score > rules[j].Score })

	return score, rules
}

func rule(name, desc string, score int) domain.RuleMatch {
	return domain.RuleMatch{Name: name, Desc: desc, Score: score}
}

func getTLD(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	l := float64(len(s))
	for _, c := range freq {
		p := c / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}
func isIPAddress(host string) bool { return ipRegex.MatchString(host) }
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}
	return float64(printableCount)/float64(len(data)) > 0.7
}
