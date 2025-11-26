package domain

// FullReport - Плоская и понятная структура
type FullReport struct {
	Target    string `json:"target"`
	Verdict   string `json:"verdict"`    // Safe, Suspicious, Dangerous
	RiskScore int    `json:"risk_score"` // 0-100
	Reason    string `json:"reason,omitempty"`

	// 1. Факты из баз данных (Точное совпадение)
	Blacklists *BlacklistInfo `json:"blacklists,omitempty"`

	// 2. Анализ поведения и текста (Подозрения)
	Heuristics []RuleMatch `json:"heuristics,omitempty"`

	// 3. Технические данные (Инфраструктура)
	Infrastructure *GeoNetInfo `json:"infrastructure,omitempty"`
}

type BlacklistInfo struct {
	Source     string `json:"source"`
	ExternalID string `json:"ext_id"`
	FirstSeen  string `json:"first_seen"`
}

type RuleMatch struct {
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Score int    `json:"score"`
}

type GeoNetInfo struct {
	Status string `json:"status"` // "Online" или "Offline"
	IP     string `json:"ip,omitempty"`

	// Вложенные структуры (указатели, чтобы скрывать через nil)
	Geo *GeoLocation `json:"geolocation,omitempty"`
	SSL *SSLInfo     `json:"ssl,omitempty"`
	DNS *DNSDetails  `json:"dns,omitempty"`
}

type GeoLocation struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp"`
}

type SSLInfo struct {
	Valid     bool   `json:"valid"`
	Issuer    string `json:"issuer"`
	AgeDays   int    `json:"age_days"`
	ExpiresIn int    `json:"expires_in"`
	IsHTTPS   bool   `json:"is_https"`
}

type DNSDetails struct {
	MXRecords []string `json:"mx_records,omitempty"`
	NSRecords []string `json:"ns_records,omitempty"`
}
