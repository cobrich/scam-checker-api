CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash CHAR(64) NOT NULL,
    source TEXT NOT NULL,
    external_id TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Создаем уникальный индекс по хешу для быстрого поиска и защиты от дублей
CREATE UNIQUE INDEX IF NOT EXISTS threats_url_hash_idx ON threats(url_hash);