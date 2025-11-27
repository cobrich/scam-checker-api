package metanalyzer

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

// AnalyzeMeta — метаданные для умного анализа
type AnalyzeMeta struct {
	IsWhitelisted bool
	IsBlacklisted bool
	DomainAgeDays int
	IsTrustedASN  bool
}

// AnalyzeWithMeta — основная функция
func AnalyzeWithMeta(rawURL string, meta *AnalyzeMeta) ([]domain.RuleMatch, int) {
	// Early whitelist/blacklist handling
	if meta != nil && meta.IsWhitelisted {
		return nil, 0
	}
	if meta != nil && meta.IsBlacklisted {
		// Если в черном списке - сразу 100, но правило добавляем для отчетности
		r := domain.RuleMatch{Name: "Found in Blacklist", Desc: "Known malicious URL", Score: 100}
		return []domain.RuleMatch{r}, 100
	}

	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		u2, err2 := url.Parse("http://" + rawURL)
		if err2 != nil {
			return nil, 0
		}
		u = u2
	}

	hostname := strings.ToLower(u.Hostname())
	cleanHost := strings.TrimPrefix(hostname, "www.")
	tokens := strings.FieldsFunc(cleanHost, func(r rune) bool { return r == '.' || r == '-' })
	path := u.Path
	pathTrim := strings.Trim(path, "/")
	query := u.RawQuery

	matchesMap := map[string]domain.RuleMatch{}

	addRule := func(name, desc string) {
		w, ok := ruleWeights[name]
		score := 10
		if ok {
			score = w.Score
		}
		matchesMap[name] = domain.RuleMatch{Name: name, Desc: desc, Score: score}
	}

	// --- RULES ---

	if u.Scheme != "https" {
		addRule("Insecure Protocol", "Non-HTTPS scheme")
	}
	if unicodeConfusables.MatchString(hostname) {
		addRule("Unicode Spoof", "Domain contains confusable characters")
	}
	if strings.Contains(hostname, "xn--") {
		addRule("Punycode", "Punycode detected")
	}

	for _, t := range tokens {
		if suspiciousKeywords[t] {
			addRule("Suspicious Keyword", "Domain token: "+t)
		}
	}
	pathLower := strings.ToLower(path)
	for kw := range suspiciousKeywords {
		if strings.Contains(pathLower, kw) {
			addRule("Suspicious Path Keyword", "Path contains: "+kw)
		}
	}

	for _, token := range tokens {
		if len(token) < 4 {
			continue
		}
		for _, b := range protectedBrands {
			if token == b {
				continue
			}
			dist := levenshtein.ComputeDistance(token, b)
			if dist == 1 || (len(b) >= 6 && dist <= 2) {
				addRule("Typosquatting", "Token '"+token+"' resembles '"+b+"'")
			}
		}
	}

	for _, b := range protectedBrands {
		if strings.Contains(cleanHost, b+"-") || strings.Contains(cleanHost, "-"+b) {
			addRule("Brand Injection", "Brand '"+b+"' injected into domain")
		}
	}

	for _, b := range protectedBrands {
		brandDot := b + "."
		if strings.Contains(cleanHost, brandDot) {
			if strings.HasPrefix(cleanHost, brandDot) {
				rest := strings.TrimPrefix(cleanHost, brandDot)
				if !strings.Contains(rest, ".") {
					continue
				}
			}
			addRule("Fake Parent Domain", "Brand '"+b+"' appears as parent/subdomain")
		}
	}

	if calculateEntropy(cleanHost) > 4.2 {
		addRule("High Entropy Domain", "Domain looks random")
	}
	for _, tok := range tokens {
		if len(tok) > 5 && calculateEntropy(tok) > 3.8 {
			addRule("High Entropy Token", "Token looks random: "+tok)
		}
	}

	if len(cleanHost) > 45 {
		addRule("Long Domain", "Length exceeds threshold")
	}
	for _, tok := range tokens {
		if len(tok) > 25 {
			addRule("Oversized Token", "Token too long: "+tok)
		}
	}

	if strings.Count(cleanHost, "-") >= 4 {
		addRule("Excessive Hyphens", "Many hyphens in domain")
	}
	if strings.Count(hostname, ".") >= 4 && !isIPAddress(hostname) {
		addRule("Deep Subdomain", "Multiple subdomain levels")
	}

	if isIPAddress(hostname) {
		addRule("IP Hostname", "Hostname is an IP")
	}

	tld := getTLD(hostname)
	if suspiciousTLDs[tld] {
		addRule("Suspicious TLD", "TLD flagged as risky: ."+tld)
	}

	if u.User != nil {
		addRule("Userinfo Abuse", "URL contains userinfo")
	}

	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" {
		addRule("Suspicious Port", "Non-standard port: "+u.Port())
	}

	if base64Like.MatchString(pathTrim) {
		if decoded, err := base64.StdEncoding.DecodeString(pathTrim); err == nil {
			if isPrintable(decoded) {
				addRule("Encoded Payload", "Base64-like payload in path")
			}
		}
	}
	if hexLike.MatchString(pathTrim) {
		addRule("Hex Payload", "Hex-like payload in path")
	}

	if strings.Contains(query, "redirect=") || strings.Contains(query, "next=") || strings.Contains(query, "url=") {
		addRule("Open Redirect", "Redirect-like query parameter")
	}
	if strings.Contains(query, "token=") || strings.Contains(query, "session=") || strings.Contains(query, "aff_id=") {
		addRule("Sensitive Query Parameter", "Suspicious query param")
	}

	if strings.Contains(rawURL, "@") && u.User == nil {
		addRule("Obfuscated URL", "Contains @ symbol")
	}

	if urlShorteners[cleanHost] {
		addRule("URL Shortener", "Shortened URL service")
	}

	if strings.Contains(rawURL, "ipfs://") || strings.Contains(hostname, "ipfs") {
		addRule("IPFS Hosting", "Decentralized storage usage")
	}
	if strings.HasSuffix(hostname, ".workers.dev") || strings.HasSuffix(hostname, ".pages.dev") {
		addRule("Cloud Worker", "Cloud worker hosting")
	}

	// Правило для свежих доменов (Freshly Registered)
	// Если мы знаем возраст (из Whois или SSL) и он меньше 14 дней
	if meta != nil && meta.DomainAgeDays > 0 && meta.DomainAgeDays <= 14 {
		addRule("Newly Registered Domain", "Domain is less than 2 weeks old")
		// В конфиге весов этому правилу нужно дать Score: 30-40 (High)
	}

	// COMBO: Brand + Sensitive Keyword (login, secure, verify)
	// Если есть инъекция бренда И слово "login" или "secure"
	_, hasBrand := matchesMap["Brand Injection"]
	_, hasFakeParent := matchesMap["Fake Parent Domain"]

	hasAuthKey := false
	for _, t := range tokens {
		if t == "login" || t == "secure" || t == "verify" || t == "auth" {
			hasAuthKey = true
			break
		}
	}

	if (hasBrand || hasFakeParent) && hasAuthKey {
		addRule("Phishing Pattern", "Brand used with auth keywords")
	}

	// --- SCORING ---

	categorySums := map[category]int{Critical: 0, High: 0, Medium: 0, Low: 0}
	matches := make([]domain.RuleMatch, 0, len(matchesMap))

	for name, m := range matchesMap {
		if w, ok := ruleWeights[name]; ok {
			m.Score = w.Score
			categorySums[w.Category] += m.Score
		} else {
			categorySums[Medium] += m.Score
		}
		matches = append(matches, m)
	}

	// Anti-FP adjustments
	if meta != nil && meta.IsTrustedASN {
		if categorySums[High] > 10 {
			categorySums[High] -= 10
		} else {
			categorySums[High] = 0
		}
	}

	if meta != nil && meta.DomainAgeDays > 365 {
		categorySums[Medium] = int(float64(categorySums[Medium]) * 0.6)
		categorySums[Low] = int(float64(categorySums[Low]) * 0.5)
	}

	multiplier := 1.0
	if categorySums[Critical] >= 50 {
		multiplier += 0.20
	}
	if categorySums[Critical] >= 100 {
		multiplier += 0.30
	}

	_, hasTypos := matchesMap["Typosquatting"]
	_, hasPuny := matchesMap["Punycode"]
	if hasTypos && hasPuny {
		multiplier += 0.25
	}

	raw := float64(categorySums[Critical])*1.5 + // Критические усиливаем
		float64(categorySums[High])*1.0 + // High считаем полностью
		float64(categorySums[Medium])*0.8 + // Medium чуть снижаем (шум)
		float64(categorySums[Low])*0.5 // Low снижаем в 2 раза

	// Применяем мультипликатор
	raw = raw * multiplier

	score := int(raw)
	if score > 100 {
		score = 100
	}

	// Final Anti-FP
	if meta != nil && meta.DomainAgeDays > 365 && categorySums[Critical]+categorySums[High] == 0 {
		score = int(float64(score) * 0.4)
	}

	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Score > matches[j].Score })
	if len(matches) > 50 {
		matches = matches[:50]
	}

	return matches, score
}

// --- CONFIG & HELPERS ---

type category string

const (
	Critical category = "critical"
	High     category = "high"
	Medium   category = "medium"
	Low      category = "low"
)

var ruleWeights = map[string]struct {
	Score    int
	Category category
}{
	"Insecure Protocol":         {8, Low},
	"Unicode Spoof":             {60, Critical},
	"Punycode":                  {45, Critical},
	"Suspicious Keyword":        {8, Low},
	"Suspicious Path Keyword":   {10, Medium},
	"Typosquatting":             {55, Critical},
	"Brand Injection":           {40, High},
	"Fake Parent Domain":        {65, Critical},
	"High Entropy Domain":       {8, Low},
	"High Entropy Token":        {12, Medium},
	"Long Domain":               {10, Low},
	"Oversized Token":           {15, Medium},
	"Excessive Hyphens":         {10, Low},
	"Deep Subdomain":            {12, Medium},
	"IP Hostname":               {40, Critical},
	"Suspicious TLD":            {8, Low},
	"Userinfo Abuse":            {40, High},
	"Suspicious Port":           {25, High},
	"Encoded Payload":           {20, Medium},
	"Hex Payload":               {18, Medium},
	"Open Redirect":             {30, High},
	"Sensitive Query Parameter": {12, Medium},
	"Obfuscated URL":            {18, Medium},
	"URL Shortener":             {25, Medium},
	"IPFS Hosting":              {30, High},
	"Cloud Worker":              {22, Medium},
	"Hex Token":                 {18, Medium},
	"Newly Registered Domain":   {40, High},
	"Phishing Pattern":          {50, Critical},
}

var (
	ipRegex            = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	unicodeConfusables = regexp.MustCompile(`[^\x00-\x7F]`)
	hexLike            = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	base64Like         = regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
)

// ---------------------------------------------------------
// 1. PROTECTED BRANDS (Топ мишеней фишинга)
// Включает: Соцсети, Банки (Глобал + РФ/СНГ), Крипто, Почты, Сервисы, Доставка
// ---------------------------------------------------------
var protectedBrands = []string{
	// Tech & Email
	"google", "gmail", "microsoft", "office365", "outlook", "onedrive",
	"apple", "icloud", "appleid", "adobe", "dropbox", "yahoo", "yandex", "mail.ru",

	// Social & Msg
	"facebook", "instagram", "whatsapp", "telegram", "twitter", "x.com",
	"linkedin", "tiktok", "snapchat", "discord", "skype", "slack", "zoom",

	// Finance & Payment
	"paypal", "stripe", "visa", "mastercard", "westernunion", "wise", "revolut",
	"chase", "wellsfargo", "bofa", "citibank", "hsbc",

	// Banks (CIS/Russia/Kazakhstan context)
	"sberbank", "sber", "tinkoff", "tbank", "vtb", "alfabank", "gazprombank",
	"kaspi", "halyk", "privatbank", "monobank",

	// Crypto (High Risk)
	"binance", "coinbase", "metamask", "trustwallet", "ledger", "trezor",
	"blockchain", "kraken", "kucoin", "bybit", "okx", "phantom", "opensea",

	// E-commerce & Services
	"amazon", "netflix", "spotify", "ebay", "booking", "airbnb", "uber",
	"roblox", "steam", "twitch", "chatgpt", "openai", "gosuslugi",

	// Logistics
	"dhl", "fedex", "ups", "usps", "royalmail", "cdek", "pochta",

	// --- French Government & Services (Critical for France) ---
	"ameli", "assurance-maladie", // Health insurance (Top target)
	"caf",                              // Family allowance
	"impots", "gouv", "france-connect", // Taxes & Login
	"cpf", "moncompteformation", // Training funds
	"laposte", "chronopost", // Post & Delivery
	"sncf", "oui-sncf", // Trains
	"pole-emploi", "france-travail",

	// --- French Banks & Insurance ---
	"credit-agricole", "creditagricole", "ca-paris",
	"societe-generale", "societegenerale",
	"bnp", "bnpparibas",
	"banquepostale", "labanquepostale",
	"lcl", "credit-lyonnais",
	"bpce", "caisse-epargne", "banque-populaire",
	"boursorama", "boursobank", "fortuneo", "hellobank",
	"axa", "groupama", "maif", "macif",

	// --- French E-commerce & Telco ---
	"leboncoin", "vinted", "cdiscount", "fnac", "darty",
	"orange", "sfr", "bouygues", "free", "free-mobile",
}

// ---------------------------------------------------------
// 2. SUSPICIOUS TLDs (Самые заспамленные зоны)
// Источник: Spamhaus "The World's Most Abused TLDs"
// ---------------------------------------------------------
var suspiciousTLDs = map[string]bool{
	// The "Classics"
	"xyz": true, "top": true, "gq": true, "tk": true, "ml": true,
	"cf": true, "ga": true, "cn": true, "ru": false,

	// New gTLDs (Cheap & Abused)
	"buzz": true, "click": true, "country": true, "icu": true, "kelly": true,
	"oops": true, "party": true, "rest": true, "review": true, "site": true,
	"work": true, "zone": true, "link": true, "live": true, "store": true,
	"shop": true, "club": true, "vip": true, "pro": true, "info": true,
	"mobi": true, "kim": true, "best": true, "cyou": true, "monster": true,
	"quest": true, "beauty": true, "hair": true, "skin": true, "mom": true,

	// Dangerous file extensions (Google Zip/Mov update)
	"zip": true, "mov": true,
}

// ---------------------------------------------------------
// 3. SUSPICIOUS KEYWORDS (Слова-триггеры)
// ---------------------------------------------------------
var suspiciousKeywords = map[string]bool{
	// Auth & Security
	"login": true, "signin": true, "log-in": true, "sign-in": true,
	"secure": true, "security": true, "account": true, "verify": true,
	"verification": true, "auth": true, "authenticate": true,
	"password": true, "credential": true, "update": true, "confirm": true,
	"recovery": true, "recover": true, "unlock": true, "suspended": true,
	"blocked": true, "restriction": true, "safe": true, "check": true,

	// Finance
	"wallet": true, "bank": true, "payment": true, "pay": true,
	"invoice": true, "billing": true, "receipt": true, "refund": true,
	"card": true, "credit": true, "withdraw": true, "transaction": true,

	// Crypto / Scams
	"airdrop": true, "claim": true, "mint": true, "presale": true,
	"giveaway": true, "bonus": true, "gift": true, "promo": true,
	"free": true, "winner": true, "prize": true, "invest": true,
	"profit": true, "mining": true,

	// Support / System
	"support": true, "help": true, "service": true, "client": true,
	"admin": true, "system": true, "server": true, "portal": true,

	// French (Specific)
	"connexion": true, "connecter": true, "securite": true, "securise": true,
	"compte": true, "verifier": true, "verification-identite": true,
	"motdepasse": true, "mdp": true, "identifiant": true,
	"mise-a-jour": true, "maj": true, "confirmer": true, "validation": true,
	"debloquer": true, "acces": true, "espace-client": true, "mon-espace": true,
	"banque": true, "bancaire": true, "paiement": true, "virement": true,
	"remboursement": true, "facture": true, "impaye": true,
	"livraison": true, "colis": true, "suivi": true, "expedition": true,
	"gendarmerie": true, "police": true, "amende": true, "convocation": true, // Police scams
	"urgent": true, "alerte": true, "info": true, "service-client": true,
}

// ---------------------------------------------------------
// 4. URL SHORTENERS (Сокращатели)
// ---------------------------------------------------------
var urlShorteners = map[string]bool{
	// Global Giants
	"bit.ly": true, "goo.gl": true, "t.co": true, "tinyurl.com": true,
	"is.gd": true, "ow.ly": true, "buff.ly": true, "rebrand.ly": true,
	"bl.ink": true, "cutt.ly": true, "shorte.st": true,

	// Common in Spam
	"bit.do": true, "x.co": true, "lnkd.in": true, "db.tt": true,
	"qr.ae": true, "adf.ly": true, "bc.vc": true, "snip.ly": true,
	"po.st": true, "q.gs": true, "v.gd": true, "tr.im": true,

	// Regional / Specific
	"clck.ru": true, "vk.cc": true, "rb.gy": true, "shorturl.at": true,
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
