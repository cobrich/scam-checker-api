package utils

import (
	"net/url"
	"strings"
)

// ExtractHostname извлекает чистый домен из строки.
// Пример: "https://www.Google.com/search" -> "google.com"
func ExtractHostname(rawURL string) (string, error) {
	// 1. Приводим к нижнему регистру и убираем пробелы
	cleanURL := strings.TrimSpace(strings.ToLower(rawURL))

	// 2. Хак для net/url: если нет протокола, парсер работает неправильно.
	// Добавляем фиктивный протокол, если его нет.
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// 3. Парсим
	u, err := url.Parse(cleanURL)
	if err != nil {
		return "", err // Невалидный URL
	}

	// 4. Получаем Hostname (без порта, если он был, например :8080)
	hostname := u.Hostname()

	// 5. Убираем "www." (обычно в белых списках хранят домены без www)
	hostname = strings.TrimPrefix(hostname, "www.")

	return hostname, nil
}