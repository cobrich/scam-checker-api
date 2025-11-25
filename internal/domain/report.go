package domain

// FullReport
type FullReport struct {
	Target    string `json:"target_url"`
	RiskScore int    `json:"risk_score"` // 0 - 100
	Verdict   string `json:"verdict"`    // "Safe", "Suspicious", "Malicious", "Dangerous"

	// Блок обнаружения угроз (почему это опасно)
	ThreatDetection ThreatDetection `json:"threat_detection"`

	// Техническая информация (факты)
	TechnicalFacts TechnicalFacts `json:"technical_facts"`
}

type ThreatDetection struct {
	// Найден ли в наших базах (URLhaus, PhishTank)
	BlacklistStatus BlacklistStatus `json:"blacklist_status"`

	// Результат эвристики (анализ строки)
	HeuristicRules []RuleMatch `json:"heuristic_rules,omitempty"` // Список сработавших правил
}

type BlacklistStatus struct {
	IsListed   bool   `json:"is_listed"`
	Source     string `json:"source,omitempty"`      // "urlhaus", "phishtank"
	ExternalID string `json:"external_id,omitempty"` // ID в базе источника
	FirstSeen  string `json:"first_seen,omitempty"`  // Дата добавления в базу
}

type RuleMatch struct {
	RuleName    string `json:"rule_name"`    // "Suspicious Keyword", "New Domain"
	Description string `json:"description"`  // "Contains 'login' keyword"
	ScoreImpact int    `json:"score_impact"` // Сколько баллов добавило (+20)
}

type TechnicalFacts struct {
	// Информация о домене
	DomainAgeDays *int `json:"domain_age_days,omitempty"` // nil если не удалось узнать
	HasMXRecords  bool `json:"has_mx_records"`            // Есть ли почта

	// Информация о SSL/TLS
	SSL *SSLInfo `json:"ssl_certificate"`

	// Геолокация сервера
	ServerLocation *GeoInfo `json:"server_location"`
	IsReachable    bool    `json:"is_reachable"` // Сайт вообще открывается?
	IP             string  `json:"ip_address,omitempty"`
	DNS            DNSInfo `json:"dns_records,omitempty"` // Детальная инфа по DNS
}

type DNSInfo struct {
	HasMX bool     `json:"has_mx"`
	MX    []string `json:"mx_records,omitempty"` // Список почтовых серверов
	NS    []string `json:"ns_records,omitempty"` // Name Servers (часто палят хостинг)
}

type SSLInfo struct {
	Valid     bool   `json:"valid"`
	Issuer    string `json:"issuer,omitempty"`   // "Let's Encrypt", "DigiCert"
	AgeDays   int    `json:"age_days,omitempty"` // Возраст сертификата
	ExpiresIn int    `json:"expires_in_days,omitempty"`
	IsHTTPS   bool   `json:"is_https"`
}

type GeoInfo struct {
	Country string `json:"country_name,omitempty"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"` // Провайдер (например "DigitalOcean" - часто для скама)
	IP      string `json:"ip_address,omitempty"`
}
