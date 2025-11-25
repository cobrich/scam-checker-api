package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository" // Импортируем, чтобы использовать структуру репозитория
	"github.com/gofiber/fiber/v2/log"
)

type PhishTankService struct {
	repo *repository.ThreatRepository
}

func NewPhishTankService(repo *repository.ThreatRepository) *PhishTankService {
	return &PhishTankService{repo: repo}
}

// Структура JSON от PhishTank
type phishTankEntry struct {
	PhishID int    `json:"phish_id"`
	URL     string `json:"url"`
}

func (s *PhishTankService) Run(ctx context.Context) error {
	url := "http://data.phishtank.com/data/online-valid.json"
	fmt.Println("Запуск обновления PhishTank...")

	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "scam-checker-bot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Info("PhishTankService: ", err)
		return err
	}
	defer resp.Body.Close()

	// Потоковый декодер
	decoder := json.NewDecoder(resp.Body)

	// Читаем открывающую скобку '['
	if _, err := decoder.Token(); err != nil {
		return err
	}

	var (
		totalRead     int64 = 0 // Сколько прочитали из JSON
		totalInserted int64 = 0 // Сколько реально попало в БД (новых)
		totalSkipped  int64 = 0 // Дубликаты
	)

	batchSize := 1000
	batch := make([]domain.Threat, 0, batchSize)

	fmt.Println("Начинаю импорт...")
	startTime := time.Now()

	for decoder.More() {
		var item phishTankEntry
		if err := decoder.Decode(&item); err != nil {
			fmt.Printf("Ошибка парсинга строки: %v\n", err)
			continue
		}

		totalRead++

		// Мапим JSON на нашу доменную модель
		threat := domain.Threat{
			URL:        item.URL,
			Source:     "phishtank",
			ExternalID: strconv.Itoa(item.PhishID),
		}
		batch = append(batch, threat)

		// Если буфер полон — сохраняем в БД
		if len(batch) >= batchSize {
			inserted, err := s.repo.SaveBatch(ctx, batch)
			if err != nil {
				fmt.Printf("КРИТИЧЕСКАЯ ОШИБКА сохранения: %v\n", err)
			}
			totalInserted += inserted
			totalSkipped += (int64(len(batch)) - inserted)

			batch = batch[:0] // Очищаем слайс (но сохраняем емкость)

			if totalRead%10000 == 0 {
				fmt.Printf("Прогресс: Прочитано %d | Новых %d | Дубли %d\n", totalRead, totalInserted, totalSkipped)
			}
		}
	}

	// Сохраняем остатки
	if len(batch) > 0 {
		inserted, err := s.repo.SaveBatch(ctx, batch)
		if err == nil {
			totalInserted += inserted
			totalSkipped += (int64(len(batch)) - inserted)
		}
	}
	duration := time.Since(startTime)

	// ФИНАЛЬНЫЙ ОТЧЕТ
	fmt.Println("==========================================")
	fmt.Println("ИМПОРТ ЗАВЕРШЕН")
	fmt.Printf("Время выполнения: %v\n", duration)
	fmt.Printf("Всего в JSON файле:  %d\n", totalRead)
	fmt.Printf("Добавлено в базу:    %d (Новые угрозы)\n", totalInserted)
	fmt.Printf("Пропущено:           %d (Уже были в базе)\n", totalSkipped)
	fmt.Println("==========================================")

	return nil
}
