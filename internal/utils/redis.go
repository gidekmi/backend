// internal/utils/redis.go
package utils

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gidekmi/backend/internal/config"
	"github.com/go-redis/redis/v8"
)

type RedisClient struct {
	Client *redis.Client
	ctx    context.Context
}

func NewRedisClient(cfg *config.Config) *RedisClient {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	ctx := context.Background()

	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	log.Println("Successfully connected to Redis")

	return &RedisClient{
		Client: rdb,
		ctx:    ctx,
	}
}

func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	return r.Client.Set(r.ctx, key, value, expiration).Err()
}

func (r *RedisClient) Get(key string) (string, error) {
	return r.Client.Get(r.ctx, key).Result()
}

func (r *RedisClient) Delete(key string) error {
	return r.Client.Del(r.ctx, key).Err()
}

func (r *RedisClient) Exists(key string) bool {
	result := r.Client.Exists(r.ctx, key)
	return result.Val() > 0
}

func (r *RedisClient) SetOTP(userID string, otp string, expiration time.Duration) error {
	key := fmt.Sprintf("otp:%s", userID)
	return r.Set(key, otp, expiration)
}

func (r *RedisClient) GetOTP(userID string) (string, error) {
	key := fmt.Sprintf("otp:%s", userID)
	return r.Get(key)
}

func (r *RedisClient) DeleteOTP(userID string) error {
	key := fmt.Sprintf("otp:%s", userID)
	return r.Delete(key)
}

func (r *RedisClient) SetRefreshToken(userID string, token string, expiration time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s", userID)
	return r.Set(key, token, expiration)
}

func (r *RedisClient) GetRefreshToken(userID string) (string, error) {
	key := fmt.Sprintf("refresh_token:%s", userID)
	return r.Get(key)
}

func (r *RedisClient) DeleteRefreshToken(userID string) error {
	key := fmt.Sprintf("refresh_token:%s", userID)
	return r.Delete(key)
}

func (r *RedisClient) Close() error {
	return r.Client.Close()
}
