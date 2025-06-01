// internal/services/jwt.go
package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/gidekmi/backend/internal/config"
	"github.com/gidekmi/backend/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService handles JWT token operations
type JWTService struct {
	secretKey   []byte
	expireHours int
}

// JWTClaims represents the JWT claims
type JWTClaims struct {
	UserID          uuid.UUID `json:"user_id"`
	Email           string    `json:"email"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	IsEmailVerified bool      `json:"is_email_verified"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// NewJWTService creates a new JWT service
func NewJWTService(cfg *config.Config) *JWTService {
	return &JWTService{
		secretKey:   []byte(cfg.JWT.Secret),
		expireHours: cfg.JWT.ExpireHours,
	}
}

// GenerateTokenPair generates both access and refresh tokens
func (j *JWTService) GenerateTokenPair(user *models.User) (*TokenPair, error) {
	// Generate access token
	accessToken, err := j.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := j.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    j.expireHours * 3600, // Convert hours to seconds
	}, nil
}

// GenerateAccessToken generates a new access token
func (j *JWTService) GenerateAccessToken(user *models.User) (string, error) {
	now := time.Now()
	expireTime := now.Add(time.Duration(j.expireHours) * time.Hour)

	claims := JWTClaims{
		UserID:          user.ID,
		Email:           user.Email,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsEmailVerified: user.IsEmailVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expireTime),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "gidekmi-api",
			Audience:  []string{"gidekmi-mobile", "gidekmi-web"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken generates a new refresh token (UUID based)
func (j *JWTService) GenerateRefreshToken(user *models.User) (string, error) {
	// For refresh tokens, we'll use UUID instead of JWT
	// This allows us to easily revoke them by deleting from database
	refreshToken := uuid.New().String()
	return refreshToken, nil
}

// ValidateAccessToken validates and parses an access token
func (j *JWTService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	// Check if token is not yet valid
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, errors.New("token not yet valid")
	}

	return claims, nil
}

// ExtractTokenFromHeader extracts token from Authorization header
func (j *JWTService) ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	// Expected format: "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		return "", errors.New("token is required")
	}

	return token, nil
}

// GetUserIDFromToken extracts user ID from a valid token
func (j *JWTService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
	claims, err := j.ValidateAccessToken(tokenString)
	if err != nil {
		return uuid.Nil, err
	}

	return claims.UserID, nil
}

// GetEmailFromToken extracts email from a valid token
func (j *JWTService) GetEmailFromToken(tokenString string) (string, error) {
	claims, err := j.ValidateAccessToken(tokenString)
	if err != nil {
		return "", err
	}

	return claims.Email, nil
}

// IsTokenExpired checks if a token is expired without full validation
func (j *JWTService) IsTokenExpired(tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secretKey, nil
	})

	if err != nil {
		return true
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return true
	}

	return claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now())
}
