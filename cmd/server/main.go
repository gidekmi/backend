// cmd/server/main.go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

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
	defer db.Close()

	// Initialize Redis
	redisClient := utils.NewRedisClient(cfg)
	defer redisClient.Close()

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
		ErrorHandler: errorHandler,
		BodyLimit:    10 * 1024 * 1024, // 10MB
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} - ${latency}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:5173,https://gidekmi.com",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	// Initialize auth handler
	authHandler := auth.NewHandler(authService, validator)

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"message": "Gidekmi API is running",
			"version": "1.0.0",
		})
	})

	// API routes
	api := app.Group("/api/v1")

	// Auth routes
	authRoutes := api.Group("/auth")
	authHandler.SetupRoutes(authRoutes)

	// Protected routes example
	protected := api.Group("/user")
	protected.Use(authMiddleware(jwtService))
	protected.Get("/profile", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		return c.JSON(fiber.Map{
			"message": "This is a protected route",
			"user_id": userID,
		})
	})

	// Start server
	port := ":" + cfg.Server.Port
	log.Printf("🚀 Server starting on port %s", cfg.Server.Port)
	log.Printf("📚 API Documentation: http://localhost%s/health", port)
	log.Printf("🔗 Environment: %s", cfg.Server.Env)

	// Graceful shutdown
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
	if err := app.Shutdown(); err != nil {
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
		"error":   true,
		"message": err.Error(),
		"code":    code,
	})
}

// authMiddleware validates JWT tokens
func authMiddleware(jwtService *services.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": "Authorization header is required",
			})
		}

		// Extract token
		token, err := jwtService.ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": err.Error(),
			})
		}

		// Validate token
		claims, err := jwtService.ValidateAccessToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
		}

		// Set user info in context
		c.Locals("user_id", claims.UserID.String())
		c.Locals("user_email", claims.Email)
		c.Locals("user_claims", claims)

		return c.Next()
	}
}
