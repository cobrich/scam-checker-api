package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/jackc/pgx/v5"
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

	// Первым делом в самом го берем только уникальные
	// с помощью мапы
	uniqueThreats := make(map[string]domain.Threat)
	for _, t := range threats {
		uniqueThreats[t.URL] = t
	}

	// Мы строим один большой запрос вида:
	// INSERT INTO threats (...) VALUES ($1,$2...), ($5,$6...)
	// ON CONFLICT (url_hash) DO NOTHING;

	query := "INSERT INTO threats (url, url_hash, source, external_id, created_at) VALUES "
	values := []interface{}{}
	placeholders := []string{}

	// Счетчик параметров ($1, $2, $3...)
	paramIdx := 1

	for _, t := range uniqueThreats {
		// Генерируем хеш прямо перед вставкой
		hash := hashURL(t.URL)

		// Добавляем плейсхолдеры: ($1, $2, $3, $4, $5)
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)",
			paramIdx, paramIdx+1, paramIdx+2, paramIdx+3, paramIdx+4))

		values = append(values, t.URL, hash, t.Source, t.ExternalID, time.Now())
		paramIdx += 5
	}

	query += strings.Join(placeholders, ",")
	query += " ON CONFLICT (url_hash) DO NOTHING;" // Самая важная часть! Игнорируем дубли.

	// Выполняем запрос
	tag, err := r.db.Exec(ctx, query, values...)
	if err != nil {
		return 0, err
	}

	return tag.RowsAffected(), err
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
func (r *ThreatRepository) GetThreatByHash(ctx context.Context, hash string) (*domain.Threat, error) {
	// Выбираем все поля, которые нам нужны для отчета
	query := `
		SELECT id, url, source, external_id, created_at 
		FROM threats 
		WHERE url_hash = $1
		LIMIT 1
	`

	var t domain.Threat

	// Используем QueryRow и Scan для маппинга данных в структуру
	err := r.db.QueryRow(ctx, query, hash).Scan(
		&t.ID,
		&t.URL,
		&t.Source,
		&t.ExternalID,
		&t.CreatedAt,
	)

	if err != nil {
		// Если запись не найдена, pgx возвращает специальную ошибку ErrNoRows.
		// Мы обрабатываем её и возвращаем nil, nil (это не ошибка системы, просто ничего нет).
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		// Если другая ошибка (например, база упала) - возвращаем её
		return nil, err
	}

	// Если всё ок - возвращаем найденную угрозу
	return &t, nil
}