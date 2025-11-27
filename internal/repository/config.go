package repository

import (
	"context"
	"github.com/cobrich/scam-checker-api/internal/domain"
)

// GetBrands загружает активные бренды
func (r *ThreatRepository) GetBrands(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, "SELECT name FROM config_brands") // Можно добавить WHERE is_active = true
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var brands []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err == nil {
			brands = append(brands, b)
		}
	}
	return brands, nil
}

// GetKeywords загружает ключевые слова
func (r *ThreatRepository) GetKeywords(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, "SELECT word, score FROM config_keywords")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keywords := make(map[string]int)
	for rows.Next() {
		var w string
		var s int
		if err := rows.Scan(&w, &s); err == nil {
			keywords[w] = s
		}
	}
	return keywords, nil
}

// GetTLDs загружает доменные зоны
func (r *ThreatRepository) GetTLDs(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, "SELECT tld, score FROM config_tlds")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tlds := make(map[string]int)
	for rows.Next() {
		var t string
		var s int
		if err := rows.Scan(&t, &s); err == nil {
			tlds[t] = s
		}
	}
	return tlds, nil
}

// GetShorteners загружает сокращатели
func (r *ThreatRepository) GetShorteners(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, "SELECT domain, score FROM config_shorteners")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	shorts := make(map[string]int)
	for rows.Next() {
		var d string
		var s int
		if err := rows.Scan(&d, &s); err == nil {
			shorts[d] = s
		}
	}
	return shorts, nil
}

// GetGeoRisks загружает страны
func (r *ThreatRepository) GetGeoRisks(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, "SELECT country_name, score FROM config_geo_risks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	geo := make(map[string]int)
	for rows.Next() {
		var c string
		var s int
		if err := rows.Scan(&c, &s); err == nil {
			geo[c] = s
		}
	}
	return geo, nil
}

// GetHosting загружает хостинг-провайдеров
func (r *ThreatRepository) GetHosting(ctx context.Context) ([]domain.HostingConfig, error) {
	rows, err := r.db.Query(ctx, "SELECT name_pattern, type, score FROM config_hosting")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []domain.HostingConfig
	for rows.Next() {
		var h domain.HostingConfig
		if err := rows.Scan(&h.Pattern, &h.Type, &h.Score); err == nil {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}