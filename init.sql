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

CREATE TABLE IF NOT EXISTS whitelist (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS whitelist_domain_idx ON whitelist(domain);

INSERT INTO whitelist (domain) VALUES 
    ('google.com'),
    ('youtube.com'),
    ('facebook.com'),
    ('instagram.com'),
    ('twitter.com'),
    ('wikipedia.org'),
    ('whatsapp.com'),
    ('amazon.com'),
    ('vk.com'),
    ('yandex.ru'),
    ('sberbank.ru'),
    ('mail.ru'),
    ('t.me'),
    ('github.com'),
    ('stackoverflow.com'),
    ('microsoft.com'),
    ('apple.com'),
    ('netflix.com'),
    ('linkedin.com')
ON CONFLICT (domain) DO NOTHING;