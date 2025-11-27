package analyzer

import (
	"encoding/base64"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/agnivade/levenshtein"
	"github.com/cobrich/scam-checker-api/internal/domain"
)

var (
	ipRegex            = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	unicodeConfusables = regexp.MustCompile(`[^\x00-\x7F]`)
	hexLike            = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)         // Hex строки (ID сессий)
	base64Like         = regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`) // Base64 (минимум 20 символов)
)

// Бренды, которые часто подделывают
var protectedBrands = []string{
	"google", "facebook", "instagram", "twitter", "paypal",
	"binance", "coinbase", "sberbank", "tinkoff", "alpha",
	"microsoft", "apple", "amazon", "netflix", "telegram",
	"whatsapp",
}

// Подозрительные доменные зоны
var suspiciousTLDs = map[string]bool{
	"xyz": true, "top": true, "gq": true, "tk": true,
	"ml": true, "cf": true, "ga": true, "buzz": true,
	"cn": true, "work": true, "click": true, "rest": true,
	"kim": true, "review": true, "country": true, "zip": true,
	"mov": true,
}

// Слова-триггеры в пути или домене
var suspiciousKeywords = map[string]int{
	"login": 7, "secure": 7, "account": 5, "update": 5,
	"verify": 7, "wallet": 10, "confirm": 5, "auth": 5,
	"support": 5, "billing": 7, "signin": 7, "recover": 7,
	"unlock": 7, "bonus": 10, "giveaway": 15, "free": 5,
    "airdrop": 15, "claim": 10,
}

var urlShorteners = []string{
	"bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "cutt.ly", "shorte.st", "clck.ru", "rb.gy",
}

//    PUBLIC FUNCTION

func Analyze(rawURL string) ([]domain.RuleMatch, int) {
	score := 0
	var rules []domain.RuleMatch

	// 0. Нормализация
	rawURL = strings.TrimSpace(rawURL)

	// 1. Парсинг URL
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		// Если URL без схемы (google.com), пробуем добавить http
		u2, err2 := url.Parse("http://" + rawURL)
		if err2 != nil {
			return nil, 0
		}
		u = u2
	}

	hostname := strings.ToLower(u.Hostname())
	cleanHost := strings.TrimPrefix(hostname, "www.")
	// Разбиваем домен на слова по точкам и дефисам
	tokens := strings.FieldsFunc(cleanHost, func(r rune) bool { return r == '.' || r == '-' })
	path := u.Path
	query := u.RawQuery

	// Rules

	// 1: Scheme (HTTP → phishing 90% случаев)

	if u.Scheme != "https" {
		score += 5
		rules = append(rules, rule("Insecure Protocol", "Non-HTTPS scheme", 20))
	}

	// 2: Unicode / Confusable chars

	if unicodeConfusables.MatchString(hostname) {
		score += 60
		rules = append(rules, rule("Unicode Spoof", "Domain contains Unicode/confusable letters", 50))
	}

	// 3: Suspicious keywords (Domain & Path)

	// Проверяем токены домена
	for _, t := range tokens {
		if v, ok := suspiciousKeywords[t]; ok {
			score += v
			rules = append(rules, rule("Suspicious Keyword in Domain", "Keyword '"+t+"' found", v))
		}
	}
	// Проверяем путь
	pathLower := strings.ToLower(path)
	for kw, v := range suspiciousKeywords {
		if strings.Contains(pathLower, kw) {
			score += v
			rules = append(rules, rule("Suspicious Keyword in Path", "Keyword '"+kw+"' found", v))
		}
	}

	// 4: Brand typosquatting (Levenshtein)

	for _, token := range tokens {
		if len(token) < 4 {
			continue
		}
		for _, brand := range protectedBrands {
			if token == brand {
				continue // Точное совпадение - это ок (если это реальный сайт, он будет в Whitelist)
			}

			dist := levenshtein.ComputeDistance(token, brand)
			// Для коротких брендов (4-5 букв) расстояние 1, для длинных - 2
			if dist == 1 || (len(brand) >= 6 && dist <= 2) {
				score += 50
				rules = append(rules, rule("Typosquatting", "Token '"+token+"' resembles '"+brand+"'", 35))
			}
		}
	}

	// 5: Brand Injection (google-secure-login.com)

	for _, brand := range protectedBrands {
		// Ищем бренд с дефисами
		if strings.Contains(cleanHost, brand+"-") || strings.Contains(cleanHost, "-"+brand) {
			score += 60
			rules = append(rules, rule("Brand Injection", "Brand '"+brand+"' injected into domain", 35))
		}
	}

	// 6: Fake Parent Domain (google.com.verify.net)

	for _, brand := range protectedBrands {
		brandDot := brand + "."
		if strings.Contains(cleanHost, brandDot) {
			// ИСПРАВЛЕНИЕ: Проверяем, что это не легитимный домен типа google.com
			// Если домен НАЧИНАЕТСЯ с бренда
			if strings.HasPrefix(cleanHost, brandDot) {
				rest := strings.TrimPrefix(cleanHost, brandDot)
				// Если в остатке нет точек (например "com", "org"), то это скорее всего легитимный домен (google.com)
				if !strings.Contains(rest, ".") {
					continue
				}
			}
			// Если мы здесь, значит бренд либо в середине, либо это google.com.evil.com
			score += 65
			rules = append(rules, rule("Fake Parent Domain", "Subdomain uses '"+brand+"'", 40))
		}
	}

	// 7: Punycode

	if strings.Contains(hostname, "xn--") {
		score += 45
		rules = append(rules, rule("Punycode", "IDN punycode detected", 40))
	}

	// 8: High entropy (Random domains & Tokens)

	// Проверяем весь хост
	if calculateEntropy(cleanHost) > 4.2 {
		score += 7
		rules = append(rules, rule("High Entropy Domain", "Looks randomly generated", 15))
	}
	// Проверяем отдельные токены (для DGA)
	for _, tok := range tokens {
		if len(tok) > 5 && calculateEntropy(tok) > 3.8 {
			score += 15
			rules = append(rules, rule("High Entropy Token", "Token '"+tok+"' looks random", 15))
		}
	}

	// 9: Long domain / Oversized Token

	if len(cleanHost) > 45 {
		score += 5
		rules = append(rules, rule("Long Domain", "Length exceeds 40 chars", 15))
	}
	for _, tok := range tokens {
		if len(tok) > 25 {
			score += 20
			rules = append(rules, rule("Oversized Token", "Token is suspiciously long", 20))
		}
	}

	// 10: Too many hyphens

	if strings.Count(cleanHost, "-") >= 4 {
		score += 10
		rules = append(rules, rule("Excessive Hyphens", "4+ hyphens", 15))
	}

	// 11: Deep subdomains

	if strings.Count(hostname, ".") >= 4 && !isIPAddress(hostname) {
		score += 10
		rules = append(rules, rule("Deep Subdomain", "4+ levels", 15))
	}

	// 12: IP as hostname

	if isIPAddress(hostname) {
		score += 30
		rules = append(rules, rule("IP Hostname", "Direct IP access", 25))
	}

	// 13: Suspicious TLD

	tld := getTLD(hostname)
	if suspiciousTLDs[tld] {
		score += 10
		rules = append(rules, rule("Suspicious TLD", "Risky TLD: ."+tld, 15))
	}

	// 14: Userinfo (google.com@evil.site)

	if u.User != nil {
		score += 40
		rules = append(rules, rule("Userinfo Abuse", "URL contains userinfo", 40))
	}

	// 15: Unusual port

	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" {
		score += 25
		rules = append(rules, rule("Suspicious Port", "Port: "+u.Port(), 20))
	}

	// 16: Base64 / Hex payload in path

	pathTrim := strings.Trim(path, "/")
	if base64Like.MatchString(pathTrim) {
		// Декодируем и проверяем, текст ли это
		if decoded, err := base64.StdEncoding.DecodeString(pathTrim); err == nil {
			if isPrintable(decoded) {
				score += 20
				rules = append(rules, rule("Encoded Payload", "Base64 in path", 25))
			}
		}
	}
	if hexLike.MatchString(pathTrim) {
		score += 20
		rules = append(rules, rule("Hex Payload", "Hex-like path", 20))
	}

	// 17: Open redirect patterns / tokens

	if strings.Contains(query, "redirect=") ||
		strings.Contains(query, "next=") ||
		strings.Contains(query, "url=") ||
		strings.Contains(query, "link=") {
		score += 25
		rules = append(rules, rule("Open Redirect", "Redirect parameter detected", 25))
	}
	if strings.Contains(query, "token=") || strings.Contains(query, "session=") || strings.Contains(query, "aff_id=") {
		score += 15
		rules = append(rules, rule("Sensitive Query Parameter", "Potential session hijacking", 15))
	}

	// 18: Obfuscated URL (@ symbol in path/query)
	if strings.Contains(rawURL, "@") && u.User == nil {
		score += 20
		rules = append(rules, rule("Obfuscated URL", "Contains @ symbol", 20))
	}

	// 19. URL Shortener
	for _, s := range urlShorteners {
		if cleanHost == s {
			score += 25
			rules = append(rules, rule("URL Shortener", "Short URL detected", 25))
			break
		}
	}

	// 20. IPFS / Workers
	if strings.Contains(rawURL, "ipfs://") || strings.Contains(hostname, "ipfs") {
		score += 35
		rules = append(rules, rule("IPFS Hosting", "Potential scam via decentralized storage", 35))
	}
	if strings.HasSuffix(hostname, ".workers.dev") || strings.HasSuffix(hostname, ".pages.dev") {
		score += 25
		rules = append(rules, rule("Cloudflare Worker", "Potential abuse of CF Workers", 25))
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	return rules, score
}

//    HELPERS

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

func isIPAddress(host string) bool {
	return ipRegex.MatchString(host)
}

// isPrintable проверяет, является ли массив байт читаемым текстом (ASCII/UTF8), а не бинарным мусором
func isPrintable(data []byte) bool {
	printableCount := 0
	for _, b := range data {
		// Проверяем ASCII printable range (32-126) + стандартные whitespace
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}
	// Если более 85% символов печатные - считаем текстом
	return float64(printableCount)/float64(len(data)) > 0.85
}
