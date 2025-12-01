-- =============================================
-- 1. ОПЕРАЦИОННЫЕ ТАБЛИЦЫ (Уже были)
-- =============================================

CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash CHAR(64) NOT NULL,
    source TEXT NOT NULL,
    external_id TEXT,
    threat_type TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS threats_url_hash_idx ON threats(url_hash);
CREATE UNIQUE INDEX IF NOT EXISTS threats_unique_source_idx ON threats(url_hash, source);

CREATE TABLE IF NOT EXISTS whitelist (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS whitelist_domain_idx ON whitelist(domain);

-- Наполняем Whitelist
INSERT INTO whitelist (domain) VALUES 
    ('google.com'), ('youtube.com'), ('facebook.com'), ('instagram.com'),
    ('twitter.com'), ('wikipedia.org'), ('whatsapp.com'), ('amazon.com'),
    ('vk.com'), ('yandex.ru'), ('sberbank.ru'), ('mail.ru'), ('t.me'),
    ('github.com'), ('stackoverflow.com'), ('microsoft.com'), ('apple.com'),
    ('netflix.com'), ('linkedin.com'), ('chatgpt.com'), ('openai.com')
ON CONFLICT (domain) DO NOTHING;


-- =============================================
-- 2. КОНФИГУРАЦИОННЫЕ ТАБЛИЦЫ (Новые)
-- =============================================

-- 2.1 Бренды
CREATE TABLE IF NOT EXISTS config_brands (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2.2 Ключевые слова
CREATE TABLE IF NOT EXISTS config_keywords (
    id SERIAL PRIMARY KEY,
    word TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2.3 TLD (Доменные зоны)
CREATE TABLE IF NOT EXISTS config_tlds (
    id SERIAL PRIMARY KEY,
    tld TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2.4 Сокращатели ссылок
CREATE TABLE IF NOT EXISTS config_shorteners (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2.5 Рискованные страны
CREATE TABLE IF NOT EXISTS config_geo_risks (
    id SERIAL PRIMARY KEY,
    country_name TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2.6 Хостинг-провайдеры (Bulletproof и Cloud)
CREATE TABLE IF NOT EXISTS config_hosting (
    id SERIAL PRIMARY KEY,
    name_pattern TEXT NOT NULL, -- Часть имени провайдера
    score INTEGER NOT NULL,     -- 40 для bulletproof, 5 для cloud
    type TEXT NOT NULL,         -- 'bulletproof' или 'cloud'
    created_at TIMESTAMP DEFAULT NOW()
);


-- =============================================
-- 3. НАПОЛНЕНИЕ ДАННЫМИ (SEED DATA)
-- =============================================

-- Бренды (Global + France + CIS)
INSERT INTO config_brands (name) VALUES 
('google'), ('gmail'), ('microsoft'), ('office365'), ('outlook'), ('onedrive'),
('apple'), ('icloud'), ('appleid'), ('adobe'), ('dropbox'), ('amazon'), ('netflix'),
('facebook'), ('instagram'), ('whatsapp'), ('telegram'), ('twitter'), ('linkedin'),
('tiktok'), ('snapchat'), ('discord'), ('zoom'), ('spotify'), ('twitch'),
('ameli'), ('assurance-maladie'), ('caf'), ('impots'), ('gouv'), ('france-connect'),
('cpf'), ('moncompteformation'), ('laposte'), ('chronopost'), ('sncf'), ('oui-sncf'),
('pole-emploi'), ('france-travail'), ('credit-agricole'), ('creditagricole'), ('ca-paris'),
('societe-generale'), ('societegenerale'), ('bnp'), ('bnpparibas'), ('banquepostale'),
('labanquepostale'), ('lcl'), ('credit-lyonnais'), ('bpce'), ('caisse-epargne'),
('banque-populaire'), ('boursorama'), ('boursobank'), ('fortuneo'), ('hellobank'),
('axa'), ('groupama'), ('maif'), ('macif'), ('leboncoin'), ('vinted'), ('cdiscount'),
('fnac'), ('darty'), ('orange'), ('sfr'), ('bouygues'), ('free'), ('free-mobile'),
('paypal'), ('stripe'), ('visa'), ('mastercard'), ('binance'), ('coinbase'), ('ledger'),
('trezor'), ('metamask'), ('blockchain'), ('kraken'), ('revolut'), ('n26'), ('wise'),
('dhl'), ('fedex'), ('ups'), ('colissimo'), ('dpd'), ('sberbank'), ('tinkoff'), ('alpha')
ON CONFLICT (name) DO NOTHING;

-- Ключевые слова
INSERT INTO config_keywords (word, score) VALUES 
('login', 20), ('signin', 20), ('secure', 20), ('security', 20),
('account', 15), ('verify', 20), ('verification', 20), ('auth', 15),
('password', 20), ('update', 15), ('confirm', 15), ('recovery', 20),
('unlock', 20), ('suspended', 20), ('blocked', 20), ('safe', 20),
('wallet', 25), ('bank', 25), ('payment', 25), ('billing', 20),
('refund', 20), ('support', 10), ('service', 10), ('admin', 20),
('bonus', 15), ('giveaway', 25), ('winner', 20), ('airdrop', 25), ('claim', 20),
-- French
('connexion', 20), ('connecter', 20), ('securite', 20), ('securise', 20),
('compte', 15), ('verifier', 20), ('motdepasse', 20), ('mdp', 20),
('identifiant', 20), ('mise-a-jour', 15), ('maj', 15), ('confirmer', 15),
('validation', 20), ('debloquer', 20), ('acces', 15), ('espace-client', 20),
('mon-espace', 20), ('banque', 25), ('bancaire', 25), ('paiement', 25),
('virement', 25), ('remboursement', 20), ('facture', 20), ('impaye', 20),
('livraison', 20), ('colis', 20), ('suivi', 20), ('expedition', 20),
('gendarmerie', 25), ('police', 25), ('amende', 25), ('convocation', 25),
('urgent', 15), ('alerte', 15), ('service-client', 10)
ON CONFLICT (word) DO NOTHING;

-- TLDs
INSERT INTO config_tlds (tld, score) VALUES 
('xyz', 10), ('top', 10), ('gq', 10), ('tk', 10), ('ml', 10),
('cf', 10), ('ga', 10), ('cn', 10), ('buzz', 10), ('click', 10),
('country', 10), ('icu', 10), ('rest', 10), ('review', 10),
('site', 10), ('work', 10), ('link', 10), ('live', 10),
('store', 10), ('shop', 10), ('club', 10), ('vip', 10),
('pro', 10), ('info', 10), ('mobi', 10), ('kim', 10),
('best', 10), ('cyou', 10), ('monster', 10), ('quest', 10),
('beauty', 10), ('mom', 10), ('zip', 10), ('mov', 10),
('cam', 10), ('bond', 10)
ON CONFLICT (tld) DO NOTHING;

-- Shorteners
INSERT INTO config_shorteners (domain, score) VALUES 
('bit.ly', 25), ('goo.gl', 25), ('t.co', 25), ('tinyurl.com', 25),
('is.gd', 25), ('ow.ly', 25), ('buff.ly', 25), ('rebrand.ly', 25),
('bl.ink', 25), ('cutt.ly', 25), ('shorte.st', 25), ('bit.do', 25),
('x.co', 25), ('lnkd.in', 25), ('db.tt', 25), ('qr.ae', 25),
('adf.ly', 25), ('bc.vc', 25), ('snip.ly', 25), ('po.st', 25),
('q.gs', 25), ('v.gd', 25), ('tr.im', 25)
ON CONFLICT (domain) DO NOTHING;

-- Geo Risks
INSERT INTO config_geo_risks (country_name, score) VALUES 
('Russia', 15), ('China', 15), ('North Korea', 50), ('Iran', 30),
('Cote D''Ivoire', 25), ('Benin', 25), ('Cameroon', 20),
('Senegal', 15), ('Mali', 15), ('Nigeria', 20),
('Turkey', 10), ('Brazil', 10), ('Vietnam', 10)
ON CONFLICT (country_name) DO NOTHING;

-- Hosting
INSERT INTO config_hosting (name_pattern, score, type) VALUES 
('FlokiNET', 40, 'bulletproof'), ('Shinjiru', 40, 'bulletproof'),
('AbeloHost', 40, 'bulletproof'), ('Offshore', 40, 'bulletproof'),
('AnonymousSpeech', 40, 'bulletproof'), ('Njalla', 40, 'bulletproof'),
('Privex', 40, 'bulletproof'), ('OrangeWebsite', 40, 'bulletproof'),
('PrivateLayer', 40, 'bulletproof'), ('Virtual Systems', 40, 'bulletproof'),
('DigitalOcean', 5, 'cloud'), ('Hetzner', 5, 'cloud'),
('OVH', 5, 'cloud'), ('Namecheap', 5, 'cloud'),
('Hostinger', 5, 'cloud'), ('Choopa', 5, 'cloud'),
('Vultr', 5, 'cloud'), ('Google LLC', 5, 'cloud'),
('Amazon.com', 5, 'cloud'), ('Cloudflare', 0, 'cloud')
-- Cloudflare 0, т.к. слишком много легитима
;










{
  "target": "http://zygospor.ru",
  "verdict": "Dangerous",
  "risk_score": 100,
  "reason": "Found in Blacklist",
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 2
  },
  "signals": [
    "Listed in stopforumspam as spam",
    "No HTTPS",
    "Insecure Protocol"
  ],
  "blacklists": [
    {
      "source": "stopforumspam",
      "ext_id": "",
      "type": "spam",
      "first_seen": "2025-12-01"
    }
  ],
  "heuristics": [
    {
      "name": "No HTTPS",
      "desc": "No secure connection",
      "score": 5
    },
    {
      "name": "Insecure Protocol",
      "desc": "Non-HTTPS scheme",
      "score": 10
    }
  ],
  "infrastructure": {
    "status": "Online",
    "ip": "5.230.123.239",
    "geolocation": {
      "country": "Germany",
      "isp": "GHOSTnet GmbH",
      "asn": 12586,
      "organization": "GHOSTnet GmbH"
    },
    "dns": {
      "mx_records": [
        "mail.zygospor.ru."
      ],
      "ns_records": [
        "ns1.zygospor.ru."
      ]
    }
  },
  "whois": {
    "registrar": "MAXNAME-RU",
    "created_date": "2023-09-25T18:37:09Z",
    "expires_date": "2026-09-25T18:37:09Z",
    "domain_age_days": 797
  }
}