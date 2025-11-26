package rest

import (
	"math"
	"net/url"

	"github.com/cobrich/scam-checker-api/internal/domain"
)

// Структура ответа как у APIVoid
type ApiVoidResponse struct {
	URL             string          `json:"url"`
	DomainBlacklist DomainBlacklist `json:"domain_blacklist"`
	SecurityChecks  SecurityChecks  `json:"security_checks"`
	ServerDetails   ServerDetails   `json:"server_details"`
	URLParts        URLParts        `json:"url_parts"`
	Redirection     Redirection     `json:"redirection"`
}

type DomainBlacklist struct {
	Detections int `json:"detections"`
}

type SecurityChecks struct {
	IsPhishingHeuristic     bool   `json:"is_phishing_heuristic"`
	IsSuspiciousDomain      bool   `json:"is_suspicious_domain"`
	IsRiskyCategory         bool   `json:"is_risky_category"`
	IsDomainRecent          string `json:"is_domain_recent"`      // "yes" / "no"
	IsDomainVeryRecent      string `json:"is_domain_very_recent"` // "yes" / "no"
	DomainAgeInYears        int    `json:"domain_age_in_years"`   // Приблизительно через SSL
	IsEmailField            bool   `json:"is_email_field"`        // false (пока нет HTML сканера)
	IsPasswordField         bool   `json:"is_password_field"`     // false
	IsCreditCardField       bool   `json:"is_credit_card_field"`  // false
	IsEmailOnQuery          bool   `json:"is_email_address_on_url_query"`
	IsSuspiciousURLPattern  bool   `json:"is_suspicious_url_pattern"`
	IsUncommonHostLength    bool   `json:"is_uncommon_host_length"`
	IsUncommonDashCharCount bool   `json:"is_uncommon_dash_char_count"`
	IsMostAbusedTLD         bool   `json:"is_most_abused_tld"`
	IsSinkholedDomain       bool   `json:"is_sinkholed_domain"`
	IsSuspiciousContent     bool   `json:"is_suspicious_content"` // false
	IsDefacedHeuristic      bool   `json:"is_defaced_heuristic"`  // false
	IsRobotsNoIndex         bool   `json:"is_robots_noindex"`     // false
	IsValidHTTPS            bool   `json:"is_valid_https"`
}

type ServerDetails struct {
	ISP string `json:"isp"`
}

type URLParts struct {
	Host  string `json:"host"`
	Path  string `json:"path"`
	Query string `json:"query"`
}

type Redirection struct {
	Found    bool `json:"found"`
	External bool `json:"external"`
}

// ConvertToApiVoid преобразует твой FullReport в формат APIVoid
func ConvertToApiVoid(r *domain.FullReport) ApiVoidResponse {
	resp := ApiVoidResponse{
		URL: r.Target,
	}

	// 1. Blacklist
	detections := 0
	if r.Blacklists != nil {
		detections = len(r.Blacklists)
	}
	resp.DomainBlacklist.Detections = detections

	// 2. URL Parts
	u, _ := url.Parse(r.Target)
	if u != nil {
		resp.URLParts = URLParts{
			Host:  u.Hostname(),
			Path:  u.Path,
			Query: u.RawQuery,
		}
	}

	// 3. Server Details
	if r.Infrastructure != nil && r.Infrastructure.Geo != nil {
		resp.ServerDetails.ISP = r.Infrastructure.Geo.ISP
	}

	// 4. Security Checks (Маппинг твоих данных)
	checks := SecurityChecks{}

	// HTTPS
	if r.Infrastructure != nil && r.Infrastructure.SSL != nil {
		checks.IsValidHTTPS = r.Infrastructure.SSL.Valid
		// Примерный возраст домена по SSL (грубая оценка, но лучше чем ничего)
		years := int(math.Floor(float64(r.Infrastructure.SSL.AgeDays) / 365.0))
		checks.DomainAgeInYears = years

		if r.Infrastructure.SSL.AgeDays < 30 {
			checks.IsDomainVeryRecent = "yes"
			checks.IsDomainRecent = "yes"
		} else if r.Infrastructure.SSL.AgeDays < 90 {
			checks.IsDomainRecent = "yes"
			checks.IsDomainVeryRecent = "no"
		} else {
			checks.IsDomainRecent = "no"
			checks.IsDomainVeryRecent = "no"
		}
	}

	// Heuristics Mapping
	// Пробегаемся по твоим правилам и включаем флаги APIVoid
	if r.Heuristics != nil {
		for _, rule := range r.Heuristics {
			switch rule.Name {
			case "Suspicious Keyword in Domain", "Suspicious Keyword in Path":
				checks.IsPhishingHeuristic = true
			case "High Entropy", "High Entropy Domain":
				checks.IsSuspiciousDomain = true
			case "Long Domain", "Oversized Token":
				checks.IsUncommonHostLength = true
			case "Multiple Hyphens", "Excessive Hyphens":
				checks.IsUncommonDashCharCount = true
			case "Suspicious TLD":
				checks.IsMostAbusedTLD = true
			case "Suspicious Path", "Encoded Payload":
				checks.IsSuspiciousURLPattern = true
			case "Sensitive Query Parameter":
				checks.IsEmailOnQuery = true // Примерно похоже
			}
		}
	}

	// Если общий риск высокий
	if r.RiskScore > 70 {
		checks.IsSuspiciousDomain = true
		checks.IsRiskyCategory = true
	}

	resp.SecurityChecks = checks

	// Redirection (пока заглушка, так как мы не ходим по редиректам)
	resp.Redirection = Redirection{Found: false, External: false}

	return resp
}
