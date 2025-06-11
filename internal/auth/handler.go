// internal/auth/handler.go
package auth

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/gidekmi/backend/internal/utils"
)

// Handler handles HTTP requests for authentication
type Handler struct {
	service   *Service
	validator *utils.Validator
}

// NewHandler creates a new auth handler
func NewHandler(service *Service, validator *utils.Validator) *Handler {
	return &Handler{
		service:   service,
		validator: validator,
	}
}

// SetupRoutes sets up authentication routes
func (h *Handler) SetupRoutes(router fiber.Router) {
	// Registration routes
	router.Post("/register/initiate", h.InitiateRegistration)
	router.Post("/register/complete", h.CompleteRegistration)
	router.Post("/register", h.Register) // Deprecated, will return error

	// Login routes
	router.Post("/login", h.Login)
	router.Post("/login/otp", h.LoginWithOTP)

	// OTP routes
	router.Post("/verify-otp", h.VerifyOTP)
	router.Post("/resend-verification", h.ResendEmailVerification)

	// Password routes
	router.Post("/forgot-password", h.ForgotPassword)
	router.Post("/reset-password", h.ResetPassword)

	// Token routes
	router.Post("/refresh", h.RefreshToken)

	// Logout routes
	router.Post("/logout", h.Logout)
	router.Post("/logout-all", h.LogoutAllDevices)

	// OAuth routes (placeholder for future implementation)
	router.Get("/google", h.GoogleOAuth)
	router.Get("/google/callback", h.GoogleOAuthCallback)

	// Auth info endpoint
	router.Get("/", h.AuthInfo)
}

// AuthInfo provides authentication endpoints information
func (h *Handler) AuthInfo(c *fiber.Ctx) error {
	baseURL := c.BaseURL()
	return c.JSON(fiber.Map{
		"service": "Authentication API",
		"version": "1.0",
		"endpoints": fiber.Map{
			"registration": fiber.Map{
				"initiate": baseURL + "/api/v1/auth/register/initiate",
				"complete": baseURL + "/api/v1/auth/register/complete",
			},
			"login": fiber.Map{
				"password": baseURL + "/api/v1/auth/login",
				"otp":      baseURL + "/api/v1/auth/login/otp",
			},
			"otp": fiber.Map{
				"verify":              baseURL + "/api/v1/auth/verify-otp",
				"resend_verification": baseURL + "/api/v1/auth/resend-verification",
			},
			"password": fiber.Map{
				"forgot": baseURL + "/api/v1/auth/forgot-password",
				"reset":  baseURL + "/api/v1/auth/reset-password",
			},
			"token": fiber.Map{
				"refresh": baseURL + "/api/v1/auth/refresh",
			},
			"logout": fiber.Map{
				"single": baseURL + "/api/v1/auth/logout",
				"all":    baseURL + "/api/v1/auth/logout-all",
			},
		},
		"status":    "operational",
		"timestamp": time.Now().Unix(),
	})
}

// InitiateRegistration starts the registration process by sending OTP
func (h *Handler) InitiateRegistration(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Sanitize inputs
	req.Email = utils.SanitizeInput(req.Email)
	req.FirstName = utils.SanitizeInput(req.FirstName)
	req.LastName = utils.SanitizeInput(req.LastName)
	if req.Phone != "" {
		req.Phone = utils.NormalizePhone(req.Phone)
	}

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Initiate registration
	response, err := h.service.InitiateRegistration(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "registration_initiation_failed",
			Message: err.Error(),
			Code:    fiber.StatusBadRequest,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// CompleteRegistration completes registration after OTP verification
func (h *Handler) CompleteRegistration(c *fiber.Ctx) error {
	var req VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Force type to email_verification for registration
	req.Type = "email_verification"

	// Sanitize inputs
	req.Email = utils.SanitizeInput(req.Email)
	req.Code = utils.SanitizeInput(req.Code)

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Complete registration
	response, err := h.service.CompleteRegistration(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "registration_completion_failed",
			Message: err.Error(),
			Code:    fiber.StatusBadRequest,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// Register handles user registration (deprecated)
func (h *Handler) Register(c *fiber.Ctx) error {
	return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
		Error:   "deprecated_endpoint",
		Message: "This endpoint is deprecated. Use /auth/register/initiate and /auth/register/complete instead.",
		Code:    fiber.StatusBadRequest,
	})
}

// Login handles user login with email and password
func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Sanitize inputs
	req.Email = utils.SanitizeInput(req.Email)

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Login user
	response, err := h.service.Login(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "login_failed",
			Message: err.Error(),
			Code:    fiber.StatusUnauthorized,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// LoginWithOTP initiates OTP-based login
func (h *Handler) LoginWithOTP(c *fiber.Ctx) error {
	var req OTPLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Sanitize inputs
	req.Email = utils.SanitizeInput(req.Email)

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Send OTP
	response, err := h.service.LoginWithOTP(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "otp_send_failed",
			Message: err.Error(),
			Code:    fiber.StatusBadRequest,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// VerifyOTP handles OTP verification
func (h *Handler) VerifyOTP(c *fiber.Ctx) error {
	var req VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Sanitize inputs
	req.Email = utils.SanitizeInput(req.Email)
	req.Code = utils.SanitizeInput(req.Code)

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Verify OTP
	response, err := h.service.VerifyOTP(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "otp_verification_failed",
			Message: err.Error(),
			Code:    fiber.StatusBadRequest,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// ResendEmailVerification resends email verification OTP
func (h *Handler) ResendEmailVerification(c *fiber.Ctx) error {
	// Get user ID from JWT token or header
	userIDStr := c.Get("X-User-ID")
	if userIDStr == "" {
		// Try to get from auth header if middleware is used
		if userID := c.Locals("user_id"); userID != nil {
			userIDStr = userID.(string)
		}
	}

	if userIDStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "unauthorized",
			Message: "User ID is required. Use X-User-ID header or authenticate with valid token",
			Code:    fiber.StatusUnauthorized,
		})
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_user_id",
			Message: "Invalid user ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Send verification email
	if err := h.service.SendEmailVerificationOTP(userID, ipAddress, userAgent); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "send_verification_failed",
			Message: err.Error(),
			Code:    fiber.StatusBadRequest,
		})
	}

	return c.Status(fiber.StatusOK).JSON(MessageResponse{
		Message: "Verification email sent successfully",
		Success: true,
	})
}

// ForgotPassword handles password reset request
func (h *Handler) ForgotPassword(c *fiber.Ctx) error {
	var req ResetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Sanitize email
	req.Email = utils.SanitizeInput(req.Email)

	// TODO: Implement forgot password logic
	// This would send a password reset email with OTP

	return c.Status(fiber.StatusOK).JSON(MessageResponse{
		Message: "If an account exists with this email, a password reset link has been sent",
		Success: true,
	})
}

// ResetPassword handles password reset with OTP
func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	var req SetNewPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// TODO: Implement password reset logic
	// This would verify OTP and update password

	return c.Status(fiber.StatusOK).JSON(MessageResponse{
		Message: "Password reset successfully",
		Success: true,
	})
}

// RefreshToken handles token refresh
func (h *Handler) RefreshToken(c *fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate request
	if errors := h.validator.ValidateStruct(req); errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Code:    fiber.StatusBadRequest,
			Fields:  errors,
		})
	}

	// Get client info
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	// Refresh token
	response, err := h.service.RefreshToken(&req, ipAddress, userAgent)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "token_refresh_failed",
			Message: err.Error(),
			Code:    fiber.StatusUnauthorized,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// Logout handles user logout
func (h *Handler) Logout(c *fiber.Ctx) error {
	// Get user ID from context (requires auth middleware)
	userIDStr := c.Locals("user_id")
	if userIDStr == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "unauthorized",
			Message: "Authentication required",
			Code:    fiber.StatusUnauthorized,
		})
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_user_id",
			Message: "Invalid user ID",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Get refresh token from request body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	c.BodyParser(&req) // Optional, might be empty

	// Logout
	if err := h.service.Logout(userID, req.RefreshToken); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "logout_failed",
			Message: err.Error(),
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusOK).JSON(MessageResponse{
		Message: "Logged out successfully",
		Success: true,
	})
}

// LogoutAllDevices handles logout from all devices
func (h *Handler) LogoutAllDevices(c *fiber.Ctx) error {
	// Get user ID from context (requires auth middleware)
	userIDStr := c.Locals("user_id")
	if userIDStr == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "unauthorized",
			Message: "Authentication required",
			Code:    fiber.StatusUnauthorized,
		})
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_user_id",
			Message: "Invalid user ID",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Logout from all devices
	if err := h.service.LogoutAllDevices(userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "logout_all_failed",
			Message: err.Error(),
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusOK).JSON(MessageResponse{
		Message: "Logged out from all devices successfully",
		Success: true,
	})
}

// GoogleOAuth handles Google OAuth initiation
func (h *Handler) GoogleOAuth(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth
	return c.Status(fiber.StatusNotImplemented).JSON(MessageResponse{
		Message: "Google OAuth not implemented yet",
		Success: false,
	})
}

// GoogleOAuthCallback handles Google OAuth callback
func (h *Handler) GoogleOAuthCallback(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth callback
	return c.Status(fiber.StatusNotImplemented).JSON(MessageResponse{
		Message: "Google OAuth callback not implemented yet",
		Success: false,
	})
}
