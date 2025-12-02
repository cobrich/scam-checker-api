package cache

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/cobrich/scam-checker-api/internal/domain"
	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisCache(redisURL string, ttl time.Duration) (*RedisCache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return &RedisCache{
		client: client,
		ttl:    ttl,
	}, nil
}

func (c *RedisCache) Get(ctx context.Context, key string) (*domain.FullReport, error) {
	val, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var report domain.FullReport
	if err := json.Unmarshal([]byte(val), &report); err != nil {
		return nil, err
	}
	slog.Info("Cache HIT", "key", key)
	return &report, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, report *domain.FullReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		slog.Error("Redis Set Error", "error", err)
	} else {
		slog.Info("Cache SET", "key", key)
	}
	return c.client.Set(ctx, key, data, c.ttl).Err()
}

func (c *RedisCache) Close() error {
	return c.client.Close()
}
