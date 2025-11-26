CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash CHAR(64) NOT NULL,
    source TEXT NOT NULL,      -- 'phishtank', 'urlhaus', 'openphish'
    external_id TEXT,          -- ID в системе источника (если есть)
    threat_type TEXT,          -- 'phishing', 'malware', 'botnet', 'spam'
    created_at TIMESTAMP DEFAULT NOW()
);

-- Индекс для быстрого поиска по хешу (НЕ уникальный, так как хеш может повторяться для разных источников)
CREATE INDEX IF NOT EXISTS threats_url_hash_idx ON threats(url_hash);

-- Уникальный индекс: один и тот же URL от одного источника не должен дублироваться
CREATE UNIQUE INDEX IF NOT EXISTS threats_unique_source_idx ON threats(url_hash, source);

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