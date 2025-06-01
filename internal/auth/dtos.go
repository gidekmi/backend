// internal/auth/dtos.go
package auth

import (
	"time"

	"github.com/gidekmi/backend/internal/models"
	"github.com/google/uuid"
)

// RegisterRequest represents user registration request
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email,max=255"`
	Password  string `json:"password" validate:"required,min=8,max=128"`
	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
	Phone     string `json:"phone,omitempty" validate:"omitempty,min=10,max=20"`
	Language  string `json:"language,omitempty" validate:"omitempty,oneof=tr en"`
}

// LoginRequest represents user login request
type LoginRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceType string `json:"device_type,omitempty" validate:"omitempty,oneof=ios android web"`
}

// OTPLoginRequest represents OTP-based login request
type OTPLoginRequest struct {
	Email      string `json:"email" validate:"required,email"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceType string `json:"device_type,omitempty" validate:"omitempty,oneof=ios android web"`
}

// VerifyOTPRequest represents OTP verification request
type VerifyOTPRequest struct {
	Email      string         `json:"email" validate:"required,email"`
	Code       string         `json:"code" validate:"required,len=6"`
	Type       models.OTPType `json:"type" validate:"required,oneof=email_verification phone_verification password_reset login"`
	DeviceID   string         `json:"device_id,omitempty"`
	DeviceType string         `json:"device_type,omitempty" validate:"omitempty,oneof=ios android web"`
}

// ResetPasswordRequest represents password reset request
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// SetNewPasswordRequest represents setting new password after reset
type SetNewPasswordRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Code        string `json:"code" validate:"required,len=6"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// RefreshTokenRequest represents refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// OAuth2CallbackRequest represents OAuth2 callback data
type OAuth2CallbackRequest struct {
	Code       string `json:"code" validate:"required"`
	State      string `json:"state" validate:"required"`
	Provider   string `json:"provider" validate:"required,oneof=google facebook apple"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceType string `json:"device_type,omitempty" validate:"omitempty,oneof=ios android web"`
}

// UpdateProfileRequest represents profile update request
type UpdateProfileRequest struct {
	FirstName            *string `json:"first_name,omitempty" validate:"omitempty,min=2,max=50"`
	LastName             *string `json:"last_name,omitempty" validate:"omitempty,min=2,max=50"`
	Phone                *string `json:"phone,omitempty" validate:"omitempty,min=10,max=20"`
	Language             *string `json:"language,omitempty" validate:"omitempty,oneof=tr en"`
	Timezone             *string `json:"timezone,omitempty"`
	NotificationsEnabled *bool   `json:"notifications_enabled,omitempty"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in"`
	User         UserResponse `json:"user"`
}

// UserResponse represents user data in responses
type UserResponse struct {
	ID                   uuid.UUID  `json:"id"`
	Email                string     `json:"email"`
	FirstName            string     `json:"first_name"`
	LastName             string     `json:"last_name"`
	Phone                *string    `json:"phone"`
	Avatar               *string    `json:"avatar"`
	IsEmailVerified      bool       `json:"is_email_verified"`
	IsPhoneVerified      bool       `json:"is_phone_verified"`
	Language             string     `json:"language"`
	Timezone             string     `json:"timezone"`
	NotificationsEnabled bool       `json:"notifications_enabled"`
	LastLoginAt          *time.Time `json:"last_login_at"`
	CreatedAt            time.Time  `json:"created_at"`
}

// TokenResponse represents token refresh response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// OTPResponse represents OTP generation response
type OTPResponse struct {
	Message   string         `json:"message"`
	ExpiresAt time.Time      `json:"expires_at"`
	Type      models.OTPType `json:"type"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// ValidationErrorResponse represents validation error response
type ValidationErrorResponse struct {
	Error   string            `json:"error"`
	Message string            `json:"message"`
	Code    int               `json:"code"`
	Fields  map[string]string `json:"fields"`
}

// OAuth2URLResponse represents OAuth2 authorization URL response
type OAuth2URLResponse struct {
	AuthURL  string `json:"auth_url"`
	State    string `json:"state"`
	Provider string `json:"provider"`
}

// ConvertUserToResponse converts User model to UserResponse
func ConvertUserToResponse(user *models.User) UserResponse {
	return UserResponse{
		ID:                   user.ID,
		Email:                user.Email,
		FirstName:            user.FirstName,
		LastName:             user.LastName,
		Phone:                user.Phone,
		Avatar:               user.Avatar,
		IsEmailVerified:      user.IsEmailVerified,
		IsPhoneVerified:      user.IsPhoneVerified,
		Language:             user.Language,
		Timezone:             user.Timezone,
		NotificationsEnabled: user.NotificationsEnabled,
		LastLoginAt:          user.LastLoginAt,
		CreatedAt:            user.CreatedAt,
	}
}
