// internal/auth/service.go - Updated with OTP-first registration
package auth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/gidekmi/backend/internal/config"
	"github.com/gidekmi/backend/internal/models"
	"github.com/gidekmi/backend/internal/services"
)

// Service handles authentication business logic
type Service struct {
	repo         *Repository
	jwtService   *services.JWTService
	emailService *services.EmailService
	otpService   *services.OTPService
	config       *config.Config
}

// RegistrationData represents pending registration data stored in Redis
type RegistrationData struct {
	Email     string `json:"email"`
	Password  string `json:"password"` // This will be hashed
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone,omitempty"`
	Language  string `json:"language"`
	CreatedAt int64  `json:"created_at"`
}

// NewService creates a new authentication service
func NewService(
	repo *Repository,
	jwtService *services.JWTService,
	emailService *services.EmailService,
	otpService *services.OTPService,
	config *config.Config,
) *Service {
	return &Service{
		repo:         repo,
		jwtService:   jwtService,
		emailService: emailService,
		otpService:   otpService,
		config:       config,
	}
}

// InitiateRegistration starts registration process by sending OTP
func (s *Service) InitiateRegistration(req *RegisterRequest, ipAddress, userAgent string) (*OTPResponse, error) {
	// Check if user already exists
	existingUser, _ := s.repo.GetUserByEmail(req.Email)
	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Check if phone is provided and already exists
	if req.Phone != "" {
		existingUserByPhone, _ := s.repo.GetUserByPhone(req.Phone)
		if existingUserByPhone != nil {
			return nil, fmt.Errorf("user with phone %s already exists", req.Phone)
		}
	}

	// Hash password before storing in Redis
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Prepare registration data
	registrationData := RegistrationData{
		Email:     req.Email,
		Password:  hashedPassword,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     req.Phone,
		Language:  req.Language,
		CreatedAt: time.Now().Unix(),
	}

	if registrationData.Language == "" {
		registrationData.Language = "tr" // Default language
	}

	// Store registration data in Redis (5 minutes TTL)
	regDataJSON, err := json.Marshal(registrationData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize registration data: %w", err)
	}

	regKey := fmt.Sprintf("registration:%s", req.Email)
	if err := s.otpService.SetRegistrationData(regKey, string(regDataJSON), 5*time.Minute); err != nil {
		return nil, fmt.Errorf("failed to store registration data: %w", err)
	}

	// Generate temporary user ID for OTP operations
	tempUserID := uuid.New()

	// Check rate limit
	canSend, waitTime, err := s.otpService.RateLimitOTP(tempUserID, models.OTPTypeEmailVerification)
	if err != nil {
		return nil, fmt.Errorf("failed to check rate limit: %w", err)
	}
	if !canSend {
		return nil, fmt.Errorf("please wait %v before requesting another code", waitTime)
	}

	// Generate OTP
	code, err := s.otpService.GenerateOTP(s.config.OTP.Length)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Store OTP in Redis
	expiresAt, err := s.otpService.StoreOTP(tempUserID, code, models.OTPTypeEmailVerification)
	if err != nil {
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	// Also store the mapping: email -> tempUserID for verification
	emailKey := fmt.Sprintf("registration_temp_id:%s", req.Email)
	if err := s.otpService.SetRegistrationData(emailKey, tempUserID.String(), 5*time.Minute); err != nil {
		return nil, fmt.Errorf("failed to store email mapping: %w", err)
	}

	// Create temporary user object for email
	tempUser := &models.User{
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	// Send OTP via email
	if err := s.emailService.SendOTPEmail(tempUser, code, models.OTPTypeEmailVerification, s.config.OTP.ExpireMinutes); err != nil {
		return nil, fmt.Errorf("failed to send OTP email: %w", err)
	}

	return &OTPResponse{
		Message:   "Registration OTP sent to your email",
		ExpiresAt: expiresAt,
		Type:      models.OTPTypeEmailVerification,
	}, nil
}

// CompleteRegistration completes registration after OTP verification
func (s *Service) CompleteRegistration(req *VerifyOTPRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Get temp user ID from email mapping
	emailKey := fmt.Sprintf("registration_temp_id:%s", req.Email)
	tempUserIDStr, err := s.otpService.GetRegistrationData(emailKey)
	if err != nil {
		return nil, fmt.Errorf("registration session not found or expired")
	}

	tempUserID, err := uuid.Parse(tempUserIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid registration session")
	}

	// Validate OTP in Redis and consume it
	valid, err := s.otpService.ConsumeOTP(tempUserID, req.Code, models.OTPTypeEmailVerification)
	if err != nil || !valid {
		return nil, fmt.Errorf("invalid or expired OTP code")
	}

	// Get registration data from Redis
	regKey := fmt.Sprintf("registration:%s", req.Email)
	regDataJSON, err := s.otpService.GetRegistrationData(regKey)
	if err != nil {
		return nil, fmt.Errorf("registration data not found or expired")
	}

	var registrationData RegistrationData
	if err := json.Unmarshal([]byte(regDataJSON), &registrationData); err != nil {
		return nil, fmt.Errorf("failed to parse registration data: %w", err)
	}

	// Create user in database
	user := &models.User{
		Email:           registrationData.Email,
		Password:        &registrationData.Password, // Already hashed
		FirstName:       registrationData.FirstName,
		LastName:        registrationData.LastName,
		Language:        registrationData.Language,
		IsEmailVerified: true, // Email is verified through OTP
	}

	if registrationData.Phone != "" {
		user.Phone = &registrationData.Phone
	}

	// Save user to database
	if err := s.repo.CreateUser(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Clean up Redis data
	s.otpService.DeleteRegistrationData(regKey)
	s.otpService.DeleteRegistrationData(emailKey)

	// Generate tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create refresh token record
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     tokenPair.RefreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if req.DeviceID != "" {
		refreshToken.DeviceID = &req.DeviceID
	}
	if req.DeviceType != "" {
		refreshToken.DeviceType = &req.DeviceType
	}

	if err := s.repo.CreateRefreshToken(refreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Send welcome email
	go func() {
		if err := s.emailService.SendWelcomeEmail(user); err != nil {
			fmt.Printf("Failed to send welcome email: %v\n", err)
		}
	}()

	return &AuthResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         ConvertUserToResponse(user),
	}, nil
}

// Register handles user registration (deprecated - use InitiateRegistration + CompleteRegistration)
func (s *Service) Register(req *RegisterRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// This method is now deprecated, redirect to new flow
	return nil, fmt.Errorf("please use /auth/register/initiate and /auth/register/complete endpoints for registration")
}

// Rest of the methods remain the same...
// (Login, LoginWithOTP, VerifyOTP, etc.)

// Login handles user login with email and password
func (s *Service) Login(req *LoginRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Get user by email
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Check if user has password (not OAuth user)
	if user.Password == nil {
		return nil, fmt.Errorf("please use social login or reset your password")
	}

	// Verify password
	if err := s.verifyPassword(*user.Password, req.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	if err := s.repo.UpdateUserLastLogin(user.ID); err != nil {
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Generate tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create refresh token record
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     tokenPair.RefreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if req.DeviceID != "" {
		refreshToken.DeviceID = &req.DeviceID
	}
	if req.DeviceType != "" {
		refreshToken.DeviceType = &req.DeviceType
	}

	if err := s.repo.CreateRefreshToken(refreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Update user last login time
	now := time.Now()
	user.LastLoginAt = &now

	return &AuthResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         ConvertUserToResponse(user),
	}, nil
}

// LoginWithOTP initiates OTP-based login
func (s *Service) LoginWithOTP(req *OTPLoginRequest, ipAddress, userAgent string) (*OTPResponse, error) {
	// Get user by email
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Check rate limit
	canSend, waitTime, err := s.otpService.RateLimitOTP(user.ID, models.OTPTypeLogin)
	if err != nil {
		return nil, fmt.Errorf("failed to check rate limit: %w", err)
	}
	if !canSend {
		return nil, fmt.Errorf("please wait %v before requesting another code", waitTime)
	}

	// Generate OTP
	code, err := s.otpService.GenerateOTP(s.config.OTP.Length)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Store OTP in Redis
	expiresAt, err := s.otpService.StoreOTP(user.ID, code, models.OTPTypeLogin)
	if err != nil {
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	// Create OTP record in database
	otpRecord := &models.OTPCode{
		UserID:    user.ID,
		Code:      code,
		Type:      models.OTPTypeLogin,
		ExpiresAt: expiresAt,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.repo.CreateOTPCode(otpRecord); err != nil {
		return nil, fmt.Errorf("failed to save OTP record: %w", err)
	}

	// Send OTP via email
	if err := s.emailService.SendOTPEmail(user, code, models.OTPTypeLogin, s.config.OTP.ExpireMinutes); err != nil {
		return nil, fmt.Errorf("failed to send OTP email: %w", err)
	}

	return &OTPResponse{
		Message:   "OTP sent to your email",
		ExpiresAt: expiresAt,
		Type:      models.OTPTypeLogin,
	}, nil
}

// VerifyOTP handles OTP verification for various purposes
func (s *Service) VerifyOTP(req *VerifyOTPRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Get user by email
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Validate OTP in Redis and consume it
	valid, err := s.otpService.ConsumeOTP(user.ID, req.Code, req.Type)
	if err != nil || !valid {
		return nil, fmt.Errorf("invalid or expired OTP code")
	}

	// Get and mark OTP as used in database
	otpRecord, err := s.repo.GetValidOTPCode(user.ID, req.Code, req.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP code")
	}

	if err := s.repo.MarkOTPAsUsed(otpRecord.ID); err != nil {
		return nil, fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// Handle different OTP types
	switch req.Type {
	case models.OTPTypeEmailVerification:
		if err := s.repo.VerifyUserEmail(user.ID); err != nil {
			return nil, fmt.Errorf("failed to verify email: %w", err)
		}
		user.IsEmailVerified = true

	case models.OTPTypePhoneVerification:
		if err := s.repo.VerifyUserPhone(user.ID); err != nil {
			return nil, fmt.Errorf("failed to verify phone: %w", err)
		}
		user.IsPhoneVerified = true

	case models.OTPTypeLogin:
		// Update last login
		if err := s.repo.UpdateUserLastLogin(user.ID); err != nil {
			fmt.Printf("Failed to update last login: %v\n", err)
		}

	case models.OTPTypePasswordReset:
		// For password reset, we'll return a special response
		// Client should use this to proceed with password reset
		return &AuthResponse{
			AccessToken:  "",
			RefreshToken: "",
			TokenType:    "",
			ExpiresIn:    0,
			User:         ConvertUserToResponse(user),
		}, nil
	}

	// Generate tokens (except for password reset)
	if req.Type != models.OTPTypePasswordReset {
		tokenPair, err := s.jwtService.GenerateTokenPair(user)
		if err != nil {
			return nil, fmt.Errorf("failed to generate tokens: %w", err)
		}

		// Create refresh token record
		refreshToken := &models.RefreshToken{
			UserID:    user.ID,
			Token:     tokenPair.RefreshToken,
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
			IPAddress: ipAddress,
			UserAgent: userAgent,
		}

		if req.DeviceID != "" {
			refreshToken.DeviceID = &req.DeviceID
		}
		if req.DeviceType != "" {
			refreshToken.DeviceType = &req.DeviceType
		}

		if err := s.repo.CreateRefreshToken(refreshToken); err != nil {
			return nil, fmt.Errorf("failed to save refresh token: %w", err)
		}

		return &AuthResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    tokenPair.ExpiresIn,
			User:         ConvertUserToResponse(user),
		}, nil
	}

	return &AuthResponse{
		User: ConvertUserToResponse(user),
	}, nil
}

// SendEmailVerificationOTP sends email verification OTP
func (s *Service) SendEmailVerificationOTP(userID uuid.UUID, ipAddress, userAgent string) error {
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if user.IsEmailVerified {
		return fmt.Errorf("email is already verified")
	}

	// Check rate limit
	canSend, waitTime, err := s.otpService.RateLimitOTP(user.ID, models.OTPTypeEmailVerification)
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	if !canSend {
		return fmt.Errorf("please wait %v before requesting another code", waitTime)
	}

	// Generate OTP
	code, err := s.otpService.GenerateOTP(s.config.OTP.Length)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Store OTP in Redis
	expiresAt, err := s.otpService.StoreOTP(user.ID, code, models.OTPTypeEmailVerification)
	if err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Create OTP record in database
	otpRecord := &models.OTPCode{
		UserID:    user.ID,
		Code:      code,
		Type:      models.OTPTypeEmailVerification,
		ExpiresAt: expiresAt,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.repo.CreateOTPCode(otpRecord); err != nil {
		return fmt.Errorf("failed to save OTP record: %w", err)
	}

	// Send OTP via email
	if err := s.emailService.SendOTPEmail(user, code, models.OTPTypeEmailVerification, s.config.OTP.ExpireMinutes); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	return nil
}

// Helper methods
func (s *Service) hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func (s *Service) verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// RefreshToken handles token refresh
func (s *Service) RefreshToken(req *RefreshTokenRequest, ipAddress, userAgent string) (*TokenResponse, error) {
	// Get and validate refresh token
	refreshToken, err := s.repo.GetValidRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Get user
	user, err := s.repo.GetUserByID(refreshToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Generate new access token
	accessToken, err := s.jwtService.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   s.config.JWT.ExpireHours * 3600,
	}, nil
}

// Logout handles user logout
func (s *Service) Logout(userID uuid.UUID, refreshToken string) error {
	// Revoke the specific refresh token
	if refreshToken != "" {
		token, err := s.repo.GetValidRefreshToken(refreshToken)
		if err == nil {
			if err := s.repo.RevokeRefreshToken(token.ID); err != nil {
				return fmt.Errorf("failed to revoke refresh token: %w", err)
			}
		}
	}

	// Invalidate all OTPs for the user
	if err := s.otpService.InvalidateAllOTPs(userID); err != nil {
		fmt.Printf("Failed to invalidate OTPs: %v\n", err)
	}

	return nil
}

// LogoutAllDevices revokes all refresh tokens for a user
func (s *Service) LogoutAllDevices(userID uuid.UUID) error {
	if err := s.repo.RevokeUserRefreshTokens(userID); err != nil {
		return fmt.Errorf("failed to revoke user refresh tokens: %w", err)
	}

	// Invalidate all OTPs for the user
	if err := s.otpService.InvalidateAllOTPs(userID); err != nil {
		fmt.Printf("Failed to invalidate OTPs: %v\n", err)
	}

	return nil
}
