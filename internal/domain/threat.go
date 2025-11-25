package domain

import "time"

// Threat - основная сущность опасного сайта
type Threat struct {
	ID         int64     `json:"id"`
	URL        string    `json:"url"`
	URLHash    string    `json:"url_hash"`
	Source     string    `json:"source"` // Например: "phishtank"
	ExternalID string    `json:"ext_id"` // ID в системе источника (phishtank_id)
	CreatedAt  time.Time `json:"created_at"`
}
