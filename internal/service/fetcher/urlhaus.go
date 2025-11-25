package fetcher

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/cobrich/scam-checker-api/internal/repository"
)

type UrlHausService struct {
	repo *repository.ThreatRepository
}

func NewUrlHausService(repo *repository.ThreatRepository) *UrlHausService {
	return &UrlHausService{repo: repo}
}

func (s *UrlHausService) Run(ctx context.Context) error {
	url := "https://urlhaus.abuse.ch/downloads/csv_online/"
	fmt.Println("Запуск обновления URLhaus...")

	client := &http.Client{Timeout: 120 * time.Second} // Файл может быть большим
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Создаем CSV ридер
	reader := csv.NewReader(resp.Body)

	// В URLhaus комментарии начинаются с #, скажем ридеру игнорировать их
	reader.Comment = '#'
	// Разрешаем переменное количество полей (на всякий случай)
	reader.FieldsPerRecord = -1

	var (
		totalRead     int64 = 0
		totalInserted int64 = 0
		totalSkipped  int64 = 0
	)

	batchSize := 1000
	batch := make([]domain.Threat, 0, batchSize)

	startTime := time.Now()

	for {
		// Читаем строку за строкой
		record, err := reader.Read()
		if err == io.EOF {
			break // Конец файла
		}
		if err != nil {
			fmt.Printf("Ошибка CSV строки: %v\n", err)
			continue
		}

		// Формат CSV URLhaus:
		// id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
		// Нам нужен индекс 0 (id) и индекс 2 (url)

		if len(record) < 3 {
			continue
		}

		id := record[0]
		url := record[2]

		totalRead++

		threat := domain.Threat{
			URL:        url,
			Source:     "urlhaus",
			ExternalID: id,
		}
		batch = append(batch, threat)

		// Сохраняем пачками
		if len(batch) >= batchSize {
			inserted, err := s.repo.SaveBatch(ctx, batch)
			if err != nil {
				fmt.Printf("Ошибка сохранения: %v\n", err)
			}
			totalInserted += inserted
			totalSkipped += (int64(len(batch)) - inserted)
			batch = batch[:0]

			if totalRead%5000 == 0 {
				fmt.Printf("URLhaus: Обработано %d...\n", totalRead)
			}
		}
	}

	// Остатки
	if len(batch) > 0 {
		inserted, _ := s.repo.SaveBatch(ctx, batch)
		totalInserted += inserted
		totalSkipped += (int64(len(batch)) - inserted)
	}

	fmt.Println("=== URLhaus ИМПОРТ ЗАВЕРШЕН ===")
	fmt.Printf("Время: %v\n", time.Since(startTime))
	fmt.Printf("Всего строк: %d\n", totalRead)
	fmt.Printf("Новых угроз: %d\n", totalInserted)
	fmt.Println("===============================")

	return nil
}
