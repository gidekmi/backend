// internal/services/otp.go
package services

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/gidekmi/backend/internal/config"
	"github.com/gidekmi/backend/internal/models"
	"github.com/gidekmi/backend/internal/utils"
	"github.com/google/uuid"
)

// OTPService handles OTP generation and validation
type OTPService struct {
	config      *config.Config
	redisClient *utils.RedisClient
}

// NewOTPService creates a new OTP service
func NewOTPService(cfg *config.Config, redisClient *utils.RedisClient) *OTPService {
	return &OTPService{
		config:      cfg,
		redisClient: redisClient,
	}
}

// GenerateOTP generates a new OTP code
func (o *OTPService) GenerateOTP(length int) (string, error) {
	if length <= 0 {
		length = o.config.OTP.Length
	}

	// Generate random number with specified length
	max := big.NewInt(int64(pow10(length)))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n.Int64()), nil
}

// StoreOTP stores OTP in Redis with TTL
func (o *OTPService) StoreOTP(userID uuid.UUID, code string, otpType models.OTPType) (time.Time, error) {
	expiration := time.Duration(o.config.OTP.ExpireMinutes) * time.Minute
	expiresAt := time.Now().Add(expiration)

	// Create Redis key with type and user ID
	key := fmt.Sprintf("otp:%s:%s", otpType, userID.String())

	// Store only the OTP code as string (simple approach)
	if err := o.redisClient.Set(key, code, expiration); err != nil {
		return time.Time{}, fmt.Errorf("failed to store OTP in Redis: %w", err)
	}

	return expiresAt, nil
}

// ValidateOTP validates an OTP code
func (o *OTPService) ValidateOTP(userID uuid.UUID, code string, otpType models.OTPType) (bool, error) {
	key := fmt.Sprintf("otp:%s:%s", otpType, userID.String())

	// Get OTP from Redis
	storedCode, err := o.redisClient.Get(key)
	if err != nil {
		return false, fmt.Errorf("OTP not found or expired")
	}

	// Simple string comparison
	if storedCode != code {
		return false, fmt.Errorf("invalid OTP code")
	}

	return true, nil
}

// ConsumeOTP validates and removes an OTP code
func (o *OTPService) ConsumeOTP(userID uuid.UUID, code string, otpType models.OTPType) (bool, error) {
	// First validate the OTP
	valid, err := o.ValidateOTP(userID, code, otpType)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, fmt.Errorf("invalid OTP code")
	}

	// Remove the OTP from Redis (consume it)
	key := fmt.Sprintf("otp:%s:%s", otpType, userID.String())
	if err := o.redisClient.Delete(key); err != nil {
		return false, fmt.Errorf("failed to consume OTP: %w", err)
	}

	return true, nil
}

// GetOTPStatus returns the status of an OTP
func (o *OTPService) GetOTPStatus(userID uuid.UUID, otpType models.OTPType) (*OTPStatus, error) {
	key := fmt.Sprintf("otp:%s:%s", otpType, userID.String())

	exists := o.redisClient.Exists(key)
	if !exists {
		return &OTPStatus{
			Exists:    false,
			ExpiresAt: nil,
		}, nil
	}

	// Get TTL
	ttl, err := o.redisClient.Client.TTL(o.redisClient.Client.Context(), key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get OTP TTL: %w", err)
	}

	expiresAt := time.Now().Add(ttl)

	return &OTPStatus{
		Exists:    true,
		ExpiresAt: &expiresAt,
	}, nil
}

// CleanupExpiredOTPs removes expired OTPs (this should be called periodically)
func (o *OTPService) CleanupExpiredOTPs() error {
	// Redis automatically handles TTL expiration, so this is mostly for logging
	// In a real implementation, you might want to scan for expired keys and log statistics
	return nil
}

// RateLimitOTP checks if user can request another OTP
func (o *OTPService) RateLimitOTP(userID uuid.UUID, otpType models.OTPType) (bool, time.Duration, error) {
	key := fmt.Sprintf("otp_rate_limit:%s:%s", otpType, userID.String())

	exists := o.redisClient.Exists(key)
	if exists {
		// Get remaining TTL
		ttl, err := o.redisClient.Client.TTL(o.redisClient.Client.Context(), key).Result()
		if err != nil {
			return false, 0, fmt.Errorf("failed to get rate limit TTL: %w", err)
		}
		return false, ttl, nil
	}

	// Set rate limit (1 minute between requests)
	rateLimitDuration := 1 * time.Minute
	if err := o.redisClient.Set(key, "1", rateLimitDuration); err != nil {
		return false, 0, fmt.Errorf("failed to set rate limit: %w", err)
	}

	return true, 0, nil
}

// InvalidateAllOTPs removes all OTPs for a user
func (o *OTPService) InvalidateAllOTPs(userID uuid.UUID) error {
	patterns := []string{
		fmt.Sprintf("otp:*:%s", userID.String()),
		fmt.Sprintf("otp_rate_limit:*:%s", userID.String()),
	}

	for _, pattern := range patterns {
		keys, err := o.redisClient.Client.Keys(o.redisClient.Client.Context(), pattern).Result()
		if err != nil {
			return fmt.Errorf("failed to get keys for pattern %s: %w", pattern, err)
		}

		if len(keys) > 0 {
			if err := o.redisClient.Client.Del(o.redisClient.Client.Context(), keys...).Err(); err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
		}
	}

	return nil
}

// OTPStatus represents the status of an OTP
type OTPStatus struct {
	Exists    bool       `json:"exists"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// Helper function to calculate power of 10
func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

// GenerateNumericOTP generates a numeric OTP with specified length
func (o *OTPService) GenerateNumericOTP(length int) (string, error) {
	if length <= 0 {
		length = 6
	}

	// Generate random digits
	otp := make([]byte, length)
	for i := range otp {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %w", err)
		}
		otp[i] = byte('0' + n.Int64())
	}

	return string(otp), nil
}

// SetRegistrationData stores registration data in Redis
func (o *OTPService) SetRegistrationData(key, data string, expiration time.Duration) error {
	return o.redisClient.Set(key, data, expiration)
}

// GetRegistrationData retrieves registration data from Redis
func (o *OTPService) GetRegistrationData(key string) (string, error) {
	return o.redisClient.Get(key)
}

// DeleteRegistrationData removes registration data from Redis
func (o *OTPService) DeleteRegistrationData(key string) error {
	return o.redisClient.Delete(key)
}

// GenerateAlphaNumericOTP generates an alphanumeric OTP
func (o *OTPService) GenerateAlphaNumericOTP(length int) (string, error) {
	if length <= 0 {
		length = 8
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	otp := make([]byte, length)

	for i := range otp {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		otp[i] = charset[n.Int64()]
	}

	return string(otp), nil
}
