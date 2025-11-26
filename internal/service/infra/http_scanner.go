package infra

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
)

var (
	titleRegex    = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	passwordRegex = regexp.MustCompile(`(?i)type=["']?password["']?`)
	ccRegex       = regexp.MustCompile(`(?i)(cc_number|card_number|cvv|cvc|credit_card)`)
)

// scanHTTP выполняет реальный запрос к сайту
func (s *InfraService) scanHTTP(ctx context.Context, urlStr string) (*domain.HTTPDetails, []domain.RuleMatch) {
	details := &domain.HTTPDetails{
		RedirectChain: []string{},
	}
	var rules []domain.RuleMatch

	// Настраиваем клиент с отслеживанием редиректов
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Игнорируем ошибки SSL при скачивании контента
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Записываем каждый шаг редиректа
			if len(via) >= 10 {
				return http.ErrUseLastResponse // Остановить после 10 редиректов
			}
			details.RedirectChain = append(details.RedirectChain, req.URL.String())
			return nil
		},
	}

	// Создаем запрос
	// Важно: если urlStr пришел без http/https, надо добавить. 
	// Но наш оркестратор уже должен был это сделать или мы берем domainName.
	// Лучше брать исходный rawURL или добавить https://
	target := urlStr
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, rules
	}
	
	// Притворяемся браузером
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, rules // Сайт недоступен по HTTP
	}
	defer resp.Body.Close()

	details.StatusCode = resp.StatusCode

	// Читаем тело (Максимум 200KB для безопасности!)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024)) 
	if err != nil {
		return details, rules
	}
	bodyStr := string(bodyBytes)

	// --- АНАЛИЗ КОНТЕНТА ---

	// 1. Title
	matches := titleRegex.FindStringSubmatch(bodyStr)
	if len(matches) > 1 {
		details.Title = matches[1]
	}

	// 2. Поиск поля пароля
	if passwordRegex.MatchString(bodyStr) {
		details.HasPasswordField = true
		rules = append(rules, domain.RuleMatch{
			Name: "Password Field Detected", 
			Desc: "Page contains a password input field", 
			Score: 10, // Само по себе не страшно, но в сочетании с другими факторами - риск
		})
	}

	// 3. Поиск полей кредитки (простая эвристика)
	if ccRegex.MatchString(bodyStr) {
		details.HasCreditCard = true
		rules = append(rules, domain.RuleMatch{
			Name: "Credit Card Field", 
			Desc: "Page requests payment details", 
			Score: 20,
		})
	}

	// 4. Проверка редиректов
	if len(details.RedirectChain) > 0 {
		// Если было много редиректов
		if len(details.RedirectChain) > 2 {
			rules = append(rules, domain.RuleMatch{
				Name: "Multiple Redirects", 
				Desc: "Chain of redirects detected", 
				Score: 15,
			})
		}
	}

	return details, rules
}