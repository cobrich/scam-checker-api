package domain

import "time"

type Threat struct {
	ID         int64     `json:"id"`
	URL        string    `json:"url"`
	URLHash    string    `json:"url_hash"`
	Source     string    `json:"source"` // Example: "phishtank"
	ExternalID string    `json:"ext_id"` // ID in sourfce
	Type       string    `json:"threat_type"` // "phishing", "malware"
	CreatedAt  time.Time `json:"created_at"`
}
