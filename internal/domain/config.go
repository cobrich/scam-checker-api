package domain

// BrandConfig соответствует таблице config_brands
type BrandConfig struct {
	Name     string
	Category string
}

// KeywordConfig соответствует таблице config_keywords
type KeywordConfig struct {
	Word  string
	Score int
}

// TLDConfig соответствует таблице config_tlds
type TLDConfig struct {
	TLD   string
	Score int
}

// ShortenerConfig соответствует таблице config_shorteners
type ShortenerConfig struct {
	Domain string
	Score  int
}

// GeoRiskConfig соответствует таблице config_geo_risks
type GeoRiskConfig struct {
	Country string
	Score   int
}

// HostingConfig соответствует таблице config_hosting
type HostingConfig struct {
	Pattern string // Часть имени (например "DigitalOcean")
	Type    string // "cloud" или "bulletproof"
	Score   int
}

// AppConfig — это большая структура, которая будет хранить ВСЕ настройки в памяти
// Мы будем передавать её в Analyzer и Infra
type AppConfig struct {
	Brands      []string
	Keywords    map[string]int
	TLDs        map[string]int
	Shorteners  map[string]int
	GeoRisks    map[string]int
	Hosting     []HostingConfig // Слайс, т.к. мы ищем подстроку (Contains), а не точное совпадение
}