package utils

import (
	"net/url"
	"strings"
)

// ExtractHostname extracting domain from url string.
// Example: "https://www.Google.com/search" -> "google.com"
func ExtractHostname(rawURL string) (string, error) {
	// 1. Make lower case and drop spaces
	cleanURL := strings.TrimSpace(strings.ToLower(rawURL))

	// 2. Add protocol if not
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// 3. Parsing
	u, err := url.Parse(cleanURL)
	if err != nil {
		return "", err // Невалидный URL
	}

	// 4. Getting Hostname without port
	hostname := u.Hostname()

	// 5. Drop www
	hostname = strings.TrimPrefix(hostname, "www.")

	return hostname, nil
}
