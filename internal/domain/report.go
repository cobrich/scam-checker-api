package domain

// FullReport
type FullReport struct {
	Target    string `json:"target"`
	Verdict   string `json:"verdict"`    // Safe, Suspicious, Dangerous
	RiskScore int    `json:"risk_score"` // 0-100
	Reason    string `json:"reason,omitempty"`

	Summary *HeuristicSummary `json:"summary,omitempty"`
	Signals []string          `json:"signals,omitempty"`

	// 1. Is in DB
	Blacklists []BlacklistInfo `json:"blacklists,omitempty"`

	// 2. Heroustics, logic analyze
	Heuristics []RuleMatch `json:"heuristics,omitempty"`

	// 3. Network info
	Infrastructure *GeoNetInfo `json:"infrastructure,omitempty"`

	// 4. WHOIS
	Whois *WhoisInfo `json:"whois,omitempty"`
}

type HeuristicSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type BlacklistInfo struct {
	Source     string `json:"source"`
	ExternalID string `json:"ext_id"`
	Type       string `json:"type"`
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

	Geo *GeoLocation `json:"geolocation,omitempty"`
	SSL *SSLInfo     `json:"ssl,omitempty"`
	DNS *DNSDetails  `json:"dns,omitempty"`

	HTTP *HTTPDetails `json:"http_scan,omitempty"`
}

type GeoLocation struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp"`
	ASN     int    `json:"asn,omitempty"`
	Org     string `json:"organization,omitempty"`
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

type HTTPDetails struct {
	StatusCode       int      `json:"status_code"`
	Title            string   `json:"page_title"`
	ContentType      string   `json:"content_type,omitempty"`
	RedirectChain    []string `json:"redirect_chain,omitempty"` // История редиректов
	HasPasswordField bool     `json:"has_password_field"`       // Нашли ли поле ввода пароля?
	HasCreditCard    bool     `json:"has_credit_card_field"`    // Нашли ли поле карты?
	IsSuspiciousJS   bool     `json:"is_suspicious_js"`         // Обфусцированный JS?
}

type WhoisInfo struct {
	Registrar     string `json:"registrar,omitempty"`    // GoDaddy, Namecheap...
	CreatedDate   string `json:"created_date,omitempty"` // 2024-01-01
	ExpiresDate   string `json:"expires_date,omitempty"`
	DomainAgeDays int    `json:"domain_age_days"`
}
