// internal/utils/redis.go - Render Key Value için güncellenmiş

package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gidekmi/backend/internal/config"
	"github.com/go-redis/redis/v8"
)

type RedisClient struct {
	Client *redis.Client
	ctx    context.Context
}

func NewRedisClient(cfg *config.Config) *RedisClient {
	ctx := context.Background()

	// Render Key Value URL parse etme
	var rdb *redis.Client

	// REDIS_URL environment variable'ını kontrol et (Render format)
	redisURL := getEnv("REDIS_URL", "")
	if redisURL != "" {
		// Parse redis://default:password@host:port format
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("Failed to parse REDIS_URL: %v", err)
			log.Printf("Falling back to individual connection parameters...")
		} else {
			rdb = redis.NewClient(opt)
			// Test connection
			if err := rdb.Ping(ctx).Err(); err == nil {
				log.Println("✅ Successfully connected to Render Key Value via REDIS_URL")
				return &RedisClient{
					Client: rdb,
					ctx:    ctx,
				}
			} else {
				log.Printf("Failed to connect via REDIS_URL: %v", err)
			}
		}
	}

	// Fallback to individual parameters
	rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Failed to connect to Redis with individual params: %v", err)
		// Return nil client if connection fails
		return &RedisClient{
			Client: nil,
			ctx:    ctx,
		}
	}

	log.Println("✅ Successfully connected to Redis")
	return &RedisClient{
		Client: rdb,
		ctx:    ctx,
	}
}

// Helper function to get environment variable
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Rest of the methods remain the same...
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	if r.Client == nil {
		return fmt.Errorf("Redis client not available")
	}
	return r.Client.Set(r.ctx, key, value, expiration).Err()
}

func (r *RedisClient) Get(key string) (string, error) {
	if r.Client == nil {
		return "", fmt.Errorf("Redis client not available")
	}
	return r.Client.Get(r.ctx, key).Result()
}

func (r *RedisClient) Delete(key string) error {
	if r.Client == nil {
		return fmt.Errorf("Redis client not available")
	}
	return r.Client.Del(r.ctx, key).Err()
}

func (r *RedisClient) Exists(key string) bool {
	if r.Client == nil {
		return false
	}
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
	if r.Client == nil {
		return nil
	}
	return r.Client.Close()
}
