// internal/auth/repository.go
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/gidekmi/backend/internal/models"
)

// Repository handles database operations for authentication
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new auth repository
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// User operations

// CreateUser creates a new user
func (r *Repository) CreateUser(user *models.User) error {
	if err := r.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUserByEmail retrieves a user by email
func (r *Repository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with email %s not found", email)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (r *Repository) GetUserByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with ID %s not found", id)
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}

// GetUserByPhone retrieves a user by phone number
func (r *Repository) GetUserByPhone(phone string) (*models.User, error) {
	var user models.User
	if err := r.db.Where("phone = ?", phone).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with phone %s not found", phone)
		}
		return nil, fmt.Errorf("failed to get user by phone: %w", err)
	}
	return &user, nil
}

// GetUserByGoogleID retrieves a user by Google ID
func (r *Repository) GetUserByGoogleID(googleID string) (*models.User, error) {
	var user models.User
	if err := r.db.Where("google_id = ?", googleID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with Google ID %s not found", googleID)
		}
		return nil, fmt.Errorf("failed to get user by Google ID: %w", err)
	}
	return &user, nil
}

// UpdateUser updates user information
func (r *Repository) UpdateUser(user *models.User) error {
	if err := r.db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdateUserLastLogin updates user's last login time
func (r *Repository) UpdateUserLastLogin(userID uuid.UUID) error {
	now := time.Now()
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("last_login_at", now).Error; err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// VerifyUserEmail marks user's email as verified
func (r *Repository) VerifyUserEmail(userID uuid.UUID) error {
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("is_email_verified", true).Error; err != nil {
		return fmt.Errorf("failed to verify user email: %w", err)
	}
	return nil
}

// VerifyUserPhone marks user's phone as verified
func (r *Repository) VerifyUserPhone(userID uuid.UUID) error {
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("is_phone_verified", true).Error; err != nil {
		return fmt.Errorf("failed to verify user phone: %w", err)
	}
	return nil
}

// UpdateUserPassword updates user's password
func (r *Repository) UpdateUserPassword(userID uuid.UUID, hashedPassword string) error {
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("password", hashedPassword).Error; err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}
	return nil
}

// DeactivateUser deactivates a user account
func (r *Repository) DeactivateUser(userID uuid.UUID) error {
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("is_active", false).Error; err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}
	return nil
}

// DeleteUser soft deletes a user
func (r *Repository) DeleteUser(userID uuid.UUID) error {
	if err := r.db.Delete(&models.User{}, userID).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// OTP operations

// CreateOTPCode creates a new OTP code record
func (r *Repository) CreateOTPCode(otp *models.OTPCode) error {
	if err := r.db.Create(otp).Error; err != nil {
		return fmt.Errorf("failed to create OTP code: %w", err)
	}
	return nil
}

// GetValidOTPCode retrieves a valid (unused and not expired) OTP code
func (r *Repository) GetValidOTPCode(userID uuid.UUID, code string, otpType models.OTPType) (*models.OTPCode, error) {
	var otpCode models.OTPCode
	if err := r.db.Where(
		"user_id = ? AND code = ? AND type = ? AND is_used = false AND expires_at > ?",
		userID, code, otpType, time.Now(),
	).First(&otpCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("valid OTP code not found")
		}
		return nil, fmt.Errorf("failed to get OTP code: %w", err)
	}
	return &otpCode, nil
}

// MarkOTPAsUsed marks an OTP code as used
func (r *Repository) MarkOTPAsUsed(otpID uuid.UUID) error {
	now := time.Now()
	if err := r.db.Model(&models.OTPCode{}).Where("id = ?", otpID).Updates(map[string]interface{}{
		"is_used": true,
		"used_at": now,
	}).Error; err != nil {
		return fmt.Errorf("failed to mark OTP as used: %w", err)
	}
	return nil
}

// InvalidateUserOTPs marks all user's OTP codes of a specific type as used
func (r *Repository) InvalidateUserOTPs(userID uuid.UUID, otpType models.OTPType) error {
	now := time.Now()
	if err := r.db.Model(&models.OTPCode{}).Where(
		"user_id = ? AND type = ? AND is_used = false",
		userID, otpType,
	).Updates(map[string]interface{}{
		"is_used": true,
		"used_at": now,
	}).Error; err != nil {
		return fmt.Errorf("failed to invalidate user OTPs: %w", err)
	}
	return nil
}

// CleanupExpiredOTPs removes expired OTP codes
func (r *Repository) CleanupExpiredOTPs() error {
	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&models.OTPCode{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired OTPs: %w", err)
	}
	return nil
}

// Refresh token operations

// CreateRefreshToken creates a new refresh token
func (r *Repository) CreateRefreshToken(refreshToken *models.RefreshToken) error {
	if err := r.db.Create(refreshToken).Error; err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// GetValidRefreshToken retrieves a valid refresh token
func (r *Repository) GetValidRefreshToken(token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	if err := r.db.Where(
		"token = ? AND is_revoked = false AND expires_at > ?",
		token, time.Now(),
	).First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("valid refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	return &refreshToken, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func (r *Repository) RevokeRefreshToken(tokenID uuid.UUID) error {
	if err := r.db.Model(&models.RefreshToken{}).Where("id = ?", tokenID).Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// RevokeUserRefreshTokens revokes all refresh tokens for a user
func (r *Repository) RevokeUserRefreshTokens(userID uuid.UUID) error {
	if err := r.db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke user refresh tokens: %w", err)
	}
	return nil
}

// CleanupExpiredRefreshTokens removes expired refresh tokens
func (r *Repository) CleanupExpiredRefreshTokens() error {
	if err := r.db.Where("expires_at < ? OR is_revoked = true", time.Now()).Delete(&models.RefreshToken{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}
	return nil
}

// Statistics and analytics

// GetUserRegistrationStats returns user registration statistics
func (r *Repository) GetUserRegistrationStats(days int) (map[string]int64, error) {
	var results []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}

	if err := r.db.Model(&models.User{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("created_at >= ?", time.Now().AddDate(0, 0, -days)).
		Group("DATE(created_at)").
		Order("date").
		Scan(&results).Error; err != nil {
		return nil, fmt.Errorf("failed to get registration stats: %w", err)
	}

	stats := make(map[string]int64)
	for _, result := range results {
		stats[result.Date] = result.Count
	}

	return stats, nil
}

// GetActiveUsersCount returns count of active users
func (r *Repository) GetActiveUsersCount() (int64, error) {
	var count int64
	if err := r.db.Model(&models.User{}).Where("is_active = true").Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to get active users count: %w", err)
	}
	return count, nil
}

// GetVerifiedUsersCount returns count of email verified users
func (r *Repository) GetVerifiedUsersCount() (int64, error) {
	var count int64
	if err := r.db.Model(&models.User{}).Where("is_email_verified = true").Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to get verified users count: %w", err)
	}
	return count, nil
}
