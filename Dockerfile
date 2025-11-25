# ЭТАП 1: Сборка (Builder)
FROM golang:alpine AS builder

WORKDIR /app

# Скачиваем зависимости (кэшируется, если go.mod не менялся)
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем бинарник
# CGO_ENABLED=0 делает бинарник статическим (работает везде)
RUN CGO_ENABLED=0 GOOS=linux go build -o scam-checker cmd/api/main.go

# ЭТАП 2: Запуск (Runner)
FROM alpine:latest

WORKDIR /root/

# Копируем бинарник из первого этапа
COPY --from=builder /app/scam-checker .

# ВАЖНО: Копируем базы GeoIP из корня проекта внутрь контейнера
# Убедись, что файлы лежат рядом с Dockerfile!
COPY GeoLite2-City.mmdb .
COPY GeoLite2-ASN.mmdb .

# Копируем .env (опционально, но лучше передавать через docker-compose)
# COPY .env .

# Открываем порт
EXPOSE 8080

# Запускаем
CMD ["./scam-checker"]