package logger

import (
	"log/slog"
	"os"
)

func Setup() {
	// Настраиваем JSON хендлер
	// LevelInfo означает, что Debug сообщения показываться не будут (можно поменять на LevelDebug)
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	// Создаем логгер, который пишет в STDOUT (стандартный вывод)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	// Делаем его дефолтным глобальным логгером
	// Теперь вызов slog.Info() будет использовать эту настройку
	slog.SetDefault(logger)
}
