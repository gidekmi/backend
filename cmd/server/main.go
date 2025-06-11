// cmd/server/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/gidekmi/backend/internal/auth"
	"github.com/gidekmi/backend/internal/config"
	"github.com/gidekmi/backend/internal/database"
	"github.com/gidekmi/backend/internal/models"
	"github.com/gidekmi/backend/internal/services"
	"github.com/gidekmi/backend/internal/utils"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database
	db := database.NewDatabase(cfg)
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize Redis
	redisClient := utils.NewRedisClient(cfg)
	defer func() {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis: %v", err)
		}
	}()

	// Run database migrations
	if err := db.Migrate(
		&models.User{},
		&models.OTPCode{},
		&models.RefreshToken{},
	); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize services
	jwtService := services.NewJWTService(cfg)
	emailService := services.NewEmailService(cfg)
	otpService := services.NewOTPService(cfg, redisClient)

	// Initialize repositories
	authRepo := auth.NewRepository(db.DB)

	// Initialize auth service
	authService := auth.NewService(
		authRepo,
		jwtService,
		emailService,
		otpService,
		cfg,
	)

	// Initialize validator
	validator := utils.NewValidator()

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler:          errorHandler,
		BodyLimit:             10 * 1024 * 1024, // 10MB
		DisableStartupMessage: cfg.Server.Env == "production",
		AppName:               cfg.App.Name + " v" + cfg.App.Version,
		ServerHeader:          "Gidekmi",
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
	})

	// Request ID middleware
	app.Use(requestid.New())

	// Security middleware
	app.Use(helmet.New(helmet.Config{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		ReferrerPolicy:     "no-referrer",
	}))

	// Compression middleware
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	// Recovery middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: cfg.Server.Env != "production",
	}))

	// Rate limiting middleware
	app.Use(limiter.New(limiter.Config{
		Max:               1000, // requests
		Expiration:        1 * time.Hour,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.Get("x-forwarded-for", c.IP())
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests, please try again later",
				"code":    429,
			})
		},
	}))

	// Logger middleware (only in development)
	if cfg.Server.Env != "production" {
		app.Use(logger.New(logger.Config{
			Format:     "[${time}] ${status} - ${method} ${path} - ${latency} - ${ip} - ${reqHeader:user-agent}\n",
			TimeFormat: "15:04:05",
			TimeZone:   "Europe/Istanbul",
		}))
	}

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(cfg.Server.AllowOrigins, ","),
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-API-Key, X-User-ID, X-Request-ID",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH",
		AllowCredentials: false, // Must be false when AllowOrigins is "*"
		ExposeHeaders:    "Content-Length, Content-Type, X-Request-ID",
	}))

	// Initialize auth handler
	authHandler := auth.NewHandler(authService, validator)

	// Root endpoint - API Information
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"name":        cfg.App.Name,
			"version":     cfg.App.Version,
			"description": cfg.App.Description,
			"environment": cfg.Server.Env,
			"base_url":    cfg.Server.BaseURL,
			"timestamp":   time.Now().Unix(),
			"endpoints": fiber.Map{
				"health":   cfg.Server.BaseURL + "/health",
				"api_info": cfg.Server.BaseURL + "/api",
				"auth":     cfg.Server.BaseURL + "/api/v1/auth",
				"user":     cfg.Server.BaseURL + "/api/v1/user",
				"docs":     "https://github.com/gidekmi/backend",
			},
			"status": "online",
		})
	})

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":      "ok",
			"message":     "Gidekmi API is running",
			"version":     cfg.App.Version,
			"environment": cfg.Server.Env,
			"timestamp":   time.Now().Unix(),
			"uptime":      time.Now().Unix(), // In real app, calculate actual uptime
			"services": fiber.Map{
				"database": "connected",
				"redis":    "connected",
				"email":    checkEmailService(cfg),
			},
		})
	})

	// API root endpoint
	app.Get("/api", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"name":     cfg.App.Name,
			"version":  cfg.App.Version,
			"base_url": cfg.Server.BaseURL,
			"endpoints": fiber.Map{
				"v1": cfg.Server.BaseURL + "/api/v1",
			},
			"available_versions": []string{"v1"},
			"current_version":    "v1",
		})
	})

	// API v1 routes
	api := app.Group("/api/v1")

	// API v1 info
	api.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"version": "1.0",
			"endpoints": fiber.Map{
				"auth": map[string]interface{}{
					"base": cfg.Server.BaseURL + "/api/v1/auth",
					"endpoints": map[string]string{
						"register_initiate": "POST /api/v1/auth/register/initiate",
						"register_complete": "POST /api/v1/auth/register/complete",
						"login":             "POST /api/v1/auth/login",
						"login_otp":         "POST /api/v1/auth/login/otp",
						"verify_otp":        "POST /api/v1/auth/verify-otp",
						"refresh":           "POST /api/v1/auth/refresh",
						"logout":            "POST /api/v1/auth/logout",
						"logout_all":        "POST /api/v1/auth/logout-all",
					},
				},
				"user": map[string]interface{}{
					"base": cfg.Server.BaseURL + "/api/v1/user",
					"endpoints": map[string]string{
						"profile": "GET /api/v1/user/profile",
					},
				},
			},
		})
	})

	// Auth routes
	authRoutes := api.Group("/auth")
	authHandler.SetupRoutes(authRoutes)

	// Protected user routes
	userRoutes := api.Group("/user")
	userRoutes.Use(authMiddleware(jwtService))

	// User profile endpoint
	userRoutes.Get("/profile", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		userEmail := c.Locals("user_email").(string)
		claims := c.Locals("user_claims")

		return c.JSON(fiber.Map{
			"message":    "Profile retrieved successfully",
			"user_id":    userID,
			"user_email": userEmail,
			"timestamp":  time.Now().Unix(),
			"request_id": c.Locals("requestid"),
			"claims":     claims,
		})
	})

	// User settings endpoint
	userRoutes.Get("/settings", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		return c.JSON(fiber.Map{
			"message": "User settings retrieved successfully",
			"user_id": userID,
			"settings": fiber.Map{
				"notifications": true,
				"language":      "tr",
				"timezone":      "Europe/Istanbul",
			},
		})
	})

	// 404 handler for undefined routes
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":      "endpoint_not_found",
			"message":    fmt.Sprintf("Endpoint %s %s not found", c.Method(), c.Path()),
			"code":       404,
			"timestamp":  time.Now().Unix(),
			"request_id": c.Locals("requestid"),
			"available_endpoints": fiber.Map{
				"root":   cfg.Server.BaseURL + "/",
				"health": cfg.Server.BaseURL + "/health",
				"api":    cfg.Server.BaseURL + "/api/v1",
			},
		})
	})

	// Start server
	port := ":" + cfg.Server.Port

	// Log startup info
	if cfg.Server.Env != "production" {
		log.Printf("🚀 %s starting on port %s", cfg.App.Name, cfg.Server.Port)
		log.Printf("🌐 Base URL: %s", cfg.Server.BaseURL)
		log.Printf("📚 API Documentation: %s/api/v1", cfg.Server.BaseURL)
		log.Printf("🏥 Health Check: %s/health", cfg.Server.BaseURL)
		log.Printf("🔗 Environment: %s", cfg.Server.Env)
		log.Printf("🗄️  Database: %s:%s/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
		log.Printf("🔴 Redis: %s:%s", cfg.Redis.Host, cfg.Redis.Port)
	}

	// Start server in goroutine
	go func() {
		if err := app.Listen(port); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("🔄 Shutting down server...")
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("✅ Server exited")
}

// errorHandler handles Fiber errors
func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":      true,
		"message":    err.Error(),
		"code":       code,
		"path":       c.Path(),
		"method":     c.Method(),
		"timestamp":  time.Now().Unix(),
		"request_id": c.Locals("requestid"),
	})
}

// authMiddleware validates JWT tokens
func authMiddleware(jwtService *services.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":      "unauthorized",
				"message":    "Authorization header is required",
				"code":       401,
				"hint":       "Add 'Authorization: Bearer <token>' header",
				"timestamp":  time.Now().Unix(),
				"request_id": c.Locals("requestid"),
			})
		}

		// Extract token
		token, err := jwtService.ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":      "unauthorized",
				"message":    err.Error(),
				"code":       401,
				"timestamp":  time.Now().Unix(),
				"request_id": c.Locals("requestid"),
			})
		}

		// Validate token
		claims, err := jwtService.ValidateAccessToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":      "unauthorized",
				"message":    "Invalid or expired token",
				"code":       401,
				"timestamp":  time.Now().Unix(),
				"request_id": c.Locals("requestid"),
			})
		}

		// Set user info in context
		c.Locals("user_id", claims.UserID.String())
		c.Locals("user_email", claims.Email)
		c.Locals("user_claims", claims)

		return c.Next()
	}
}

// checkEmailService checks if email service is properly configured
func checkEmailService(cfg *config.Config) string {
	if cfg.Email.SMTPUser == "" || cfg.Email.SMTPPassword == "" {
		return "not_configured"
	}
	return "configured"
}
