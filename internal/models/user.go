// internal/models/user.go
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Email     string    `json:"email" gorm:"uniqueIndex;not null" validate:"required,email"`
	Password  *string   `json:"-" gorm:"type:varchar(255)"` // Nullable for OAuth users
	FirstName string    `json:"first_name" gorm:"not null" validate:"required,min=2,max=50"`
	LastName  string    `json:"last_name" gorm:"not null" validate:"required,min=2,max=50"`
	Phone     *string   `json:"phone" gorm:"type:varchar(20);uniqueIndex"`
	Avatar    *string   `json:"avatar" gorm:"type:text"`

	// Account status
	IsEmailVerified bool       `json:"is_email_verified" gorm:"default:false"`
	IsPhoneVerified bool       `json:"is_phone_verified" gorm:"default:false"`
	IsActive        bool       `json:"is_active" gorm:"default:true"`
	LastLoginAt     *time.Time `json:"last_login_at"`

	// OAuth providers
	GoogleID   *string `json:"-" gorm:"type:varchar(255);uniqueIndex"`
	FacebookID *string `json:"-" gorm:"type:varchar(255);uniqueIndex"`
	AppleID    *string `json:"-" gorm:"type:varchar(255);uniqueIndex"`

	// Preferences
	Language             string `json:"language" gorm:"default:'tr'" validate:"required,oneof=tr en"`
	Timezone             string `json:"timezone" gorm:"default:'Europe/Istanbul'"`
	NotificationsEnabled bool   `json:"notifications_enabled" gorm:"default:true"`

	// Metadata
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Relations
	OTPCodes      []OTPCode      `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	RefreshTokens []RefreshToken `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// BeforeCreate will set a UUID rather than numeric ID
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for User model
func (User) TableName() string {
	return "users"
}

// GetFullName returns the full name of the user
func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

// IsOAuthUser checks if user registered via OAuth
func (u *User) IsOAuthUser() bool {
	return u.GoogleID != nil || u.FacebookID != nil || u.AppleID != nil
}

// HasPassword checks if user has a password set
func (u *User) HasPassword() bool {
	return u.Password != nil && *u.Password != ""
}

// OTPCode represents an OTP verification code
type OTPCode struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	Code      string     `json:"code" gorm:"not null;size:10"`
	Type      OTPType    `json:"type" gorm:"not null" validate:"required,oneof=email_verification phone_verification password_reset login"`
	ExpiresAt time.Time  `json:"expires_at" gorm:"not null"`
	UsedAt    *time.Time `json:"used_at"`
	IsUsed    bool       `json:"is_used" gorm:"default:false"`

	// Metadata
	IPAddress string    `json:"ip_address" gorm:"type:varchar(45)"`
	UserAgent string    `json:"user_agent" gorm:"type:text"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relations
	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// OTPType represents the type of OTP
type OTPType string

const (
	OTPTypeEmailVerification OTPType = "email_verification"
	OTPTypePhoneVerification OTPType = "phone_verification"
	OTPTypePasswordReset     OTPType = "password_reset"
	OTPTypeLogin             OTPType = "login"
)

// BeforeCreate will set a UUID for OTPCode
func (o *OTPCode) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for OTPCode model
func (OTPCode) TableName() string {
	return "otp_codes"
}

// IsExpired checks if the OTP code has expired
func (o *OTPCode) IsExpired() bool {
	return time.Now().After(o.ExpiresAt)
}

// IsValid checks if the OTP code is valid for use
func (o *OTPCode) IsValid() bool {
	return !o.IsUsed && !o.IsExpired()
}

// RefreshToken represents a refresh token for JWT authentication
type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"token" gorm:"not null;uniqueIndex;size:255"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	IsRevoked bool      `json:"is_revoked" gorm:"default:false"`

	// Device info
	DeviceID   *string `json:"device_id" gorm:"type:varchar(255)"`
	DeviceType *string `json:"device_type" gorm:"type:varchar(50)"` // ios, android, web
	IPAddress  string  `json:"ip_address" gorm:"type:varchar(45)"`
	UserAgent  string  `json:"user_agent" gorm:"type:text"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relations
	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// BeforeCreate will set a UUID for RefreshToken
func (r *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for RefreshToken model
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsExpired checks if the refresh token has expired
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsValid checks if the refresh token is valid for use
func (r *RefreshToken) IsValid() bool {
	return !r.IsRevoked && !r.IsExpired()
}
