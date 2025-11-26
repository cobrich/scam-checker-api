package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	// 1. Подготовка данных
	// Мы НЕ фильтруем уникальные в Go, так как уникальность теперь (url_hash, source).
	// Просто шлем всё в базу.

	query := "INSERT INTO threats (url, url_hash, source, external_id, threat_type, created_at) VALUES "
	values := []interface{}{}
	placeholders := []string{}

	paramIdx := 1

	for _, t := range threats {
		hash := hashURL(t.URL)

		// Формируем плейсхолдеры ($1, $2, $3, $4, $5, $6)
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)",
			paramIdx, paramIdx+1, paramIdx+2, paramIdx+3, paramIdx+4, paramIdx+5))

		// ВАЖНО: Проверяем типы данных
		// url -> string
		// hash -> string
		// source -> string
		// external_id -> string
		// threat_type -> string
		// created_at -> time.Time

		values = append(values, t.URL, hash, t.Source, t.ExternalID, t.Type, time.Now())
		paramIdx += 6
	}

	query += strings.Join(placeholders, ",")
	// ВАЖНО: Конфликт теперь по паре (url_hash, source)
	query += " ON CONFLICT (url_hash, source) DO NOTHING;"

	// Выполняем запрос
	tag, err := r.db.Exec(ctx, query, values...)
	if err != nil {
		// Логируем сам запрос для отладки (если ошибка останется)
		// fmt.Println("DEBUG QUERY ERROR:", err)
		return 0, err
	}

	return tag.RowsAffected(), nil
}

func (r *ThreatRepository) ExistsByHash(ctx context.Context, hash string) (bool, error) {
	var exists bool
	// SELECT EXISTS вернет true, если запись найдена, иначе false
	query := "SELECT EXISTS(SELECT 1 FROM threats WHERE url_hash = $1)"

	err := r.db.QueryRow(ctx, query, hash).Scan(&exists)
	return exists, err
}

// GetThreatByHash ищет угрозу по хешу и возвращает указатель на структуру Threat.
// Если угроза не найдена, возвращает nil (и nil ошибку).
func (r *ThreatRepository) GetThreatsByHash(ctx context.Context, hash string) ([]domain.Threat, error) {
	// Выбираем все поля, которые нам нужны для отчета
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

// GetWhitelist загружает все домены из таблицы whitelist
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
			continue // Пропускаем битые строки, если вдруг
		}
		domains = append(domains, d)
	}

	return domains, rows.Err()
}
