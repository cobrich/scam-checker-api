package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ThreatRepository struct {
	db *pgxpool.Pool
}

func NewThreatRepository(db *pgxpool.Pool) *ThreatRepository {
	return &ThreatRepository{db: db}
}

func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

func (r *ThreatRepository) SaveBatch(ctx context.Context, threats []domain.Threat) (int64, error) {
	if len(threats) == 0 {
		return 0, nil
	}

	query := "INSERT INTO threats (url, url_hash, source, external_id, threat_type, created_at) VALUES "
	values := []interface{}{}
	placeholders := []string{}

	paramIdx := 1

	for _, t := range threats {
		hash := hashURL(t.URL)

		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)",
			paramIdx, paramIdx+1, paramIdx+2, paramIdx+3, paramIdx+4, paramIdx+5))

		values = append(values, t.URL, hash, t.Source, t.ExternalID, t.Type, time.Now())
		paramIdx += 6
	}

	query += strings.Join(placeholders, ",")
	query += " ON CONFLICT (url_hash, source) DO NOTHING;"

	tag, err := r.db.Exec(ctx, query, values...)
	if err != nil {
		slog.Info("DEBUG QUERY ERROR", "error", err)
		return 0, err
	}

	return tag.RowsAffected(), nil
}

func (r *ThreatRepository) ExistsByHash(ctx context.Context, hash string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM threats WHERE url_hash = $1)"

	err := r.db.QueryRow(ctx, query, hash).Scan(&exists)
	return exists, err
}

func (r *ThreatRepository) GetThreatsByHash(ctx context.Context, hash string) ([]domain.Threat, error) {
	query := `
		SELECT id, url, source, external_id, threat_type, created_at 
		FROM threats 
		WHERE url_hash = $1
	`

	rows, err := r.db.Query(ctx, query, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []domain.Threat
	for rows.Next() {
		var t domain.Threat
		if err := rows.Scan(&t.ID, &t.URL, &t.Source, &t.ExternalID, &t.Type, &t.CreatedAt); err == nil {
			threats = append(threats, t)
		}
	}
	return threats, nil
}

func (r *ThreatRepository) GetWhitelist(ctx context.Context) ([]string, error) {
	query := "SELECT domain FROM whitelist"

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			continue
		}
		domains = append(domains, d)
	}

	return domains, rows.Err()
}
