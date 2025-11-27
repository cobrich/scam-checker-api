-- =============================================
-- 1. ОПЕРАЦИОННЫЕ ТАБЛИЦЫ (Уже есть)
-- =============================================

-- Таблица с угрозами (Blacklists)
CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash CHAR(64) NOT NULL,
    source TEXT NOT NULL,       -- 'phishtank', 'urlhaus'
    external_id TEXT,
    threat_type TEXT,           -- 'phishing', 'malware'
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS threats_url_hash_idx ON threats(url_hash);
CREATE UNIQUE INDEX IF NOT EXISTS threats_unique_source_idx ON threats(url_hash, source);

-- Таблица белого списка (Whitelist)
CREATE TABLE IF NOT EXISTS whitelist (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    category TEXT,              -- 'search_engine', 'bank', 'social'
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS whitelist_domain_idx ON whitelist(domain);


-- =============================================
-- 2. КОНФИГУРАЦИОННЫЕ ТАБЛИЦЫ (Эвристика)
-- =============================================

-- Защищаемые бренды (вместо var protectedBrands)
CREATE TABLE IF NOT EXISTS config_brands (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,  -- 'google', 'ameli', 'sberbank'
    category TEXT,              -- 'bank', 'gov', 'crypto'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Подозрительные ключевые слова (вместо var suspiciousKeywords)
CREATE TABLE IF NOT EXISTS config_keywords (
    id SERIAL PRIMARY KEY,
    word TEXT NOT NULL UNIQUE,  -- 'login', 'connexion'
    score INTEGER NOT NULL,     -- 20, 15
    language TEXT DEFAULT 'en', -- 'en', 'fr', 'ru' (полезно для фильтрации)
    is_active BOOLEAN DEFAULT TRUE
);

-- Подозрительные доменные зоны (вместо var suspiciousTLDs)
CREATE TABLE IF NOT EXISTS config_tlds (
    id SERIAL PRIMARY KEY,
    tld TEXT NOT NULL UNIQUE,   -- 'xyz', 'top'
    score INTEGER NOT NULL,     -- 15
    is_active BOOLEAN DEFAULT TRUE
);

-- Сокращатели ссылок (вместо var urlShorteners)
CREATE TABLE IF NOT EXISTS config_shorteners (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE, -- 'bit.ly', 't.co'
    is_active BOOLEAN DEFAULT TRUE
);


-- =============================================
-- 3. КОНФИГУРАЦИОННЫЕ ТАБЛИЦЫ (Инфраструктура)
-- =============================================

-- Рискованные страны (вместо var riskyCountries)
CREATE TABLE IF NOT EXISTS config_geo_risks (
    id SERIAL PRIMARY KEY,
    country_name TEXT NOT NULL UNIQUE, -- 'China', 'Russia'
    score INTEGER NOT NULL,            -- 20, 15
    is_active BOOLEAN DEFAULT TRUE
);

-- Хостинг-провайдеры (вместо bulletproofHosts и cloudProviders)
CREATE TABLE IF NOT EXISTS config_hosting_providers (
    id SERIAL PRIMARY KEY,
    name_pattern TEXT NOT NULL, -- 'DigitalOcean', 'FlokiNET'
    type TEXT NOT NULL,         -- 'bulletproof', 'cloud', 'trusted'
    score INTEGER NOT NULL,     -- 40 (bulletproof), 5 (cloud), -10 (trusted)
    is_active BOOLEAN DEFAULT TRUE
);