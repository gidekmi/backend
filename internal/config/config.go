// internal/config/config.go
package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Email    EmailConfig
	OAuth    OAuthConfig
	OTP      OTPConfig
	App      AppConfig
}

type ServerConfig struct {
	Port         string
	Env          string
	BaseURL      string
	AllowOrigins []string
	TrustedIPs   []string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type JWTConfig struct {
	Secret      string
	ExpireHours int
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
}

type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
}

type OTPConfig struct {
	ExpireMinutes int
	Length        int
}

type AppConfig struct {
	Name        string
	Version     string
	Description string
}

func LoadConfig() *Config {
	// Load .env file (optional in production)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Determine environment
	env := getEnv("ENV", "development")
	isProduction := env == "production"

	// Base URL configuration
	baseURL := getEnv("BASE_URL", "http://localhost:8080")
	if isProduction && baseURL == "http://localhost:8080" {
		baseURL = "https://gidekmi-api.onrender.com" // Default Render URL
	}

	// CORS origins
	allowOrigins := getCORSOrigins(isProduction, baseURL)

	config := &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8080"),
			Env:          env,
			BaseURL:      baseURL,
			AllowOrigins: allowOrigins,
			TrustedIPs:   getTrustedIPs(isProduction),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			DBName:   getEnv("DB_NAME", "gidekmi_db"),
			SSLMode:  getSSLMode(isProduction),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			Secret:      getEnv("JWT_SECRET", "your_super_secret_jwt_key_here_change_in_production"),
			ExpireHours: getEnvAsInt("JWT_EXPIRE_HOURS", 24),
		},
		Email: EmailConfig{
			SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:     getEnv("SMTP_PORT", "587"),
			SMTPUser:     getEnv("SMTP_USER", ""),
			SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		},
		OAuth: OAuthConfig{
			GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
			GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
			GoogleRedirectURL:  getGoogleRedirectURL(baseURL),
		},
		OTP: OTPConfig{
			ExpireMinutes: getEnvAsInt("OTP_EXPIRE_MINUTES", 5),
			Length:        getEnvAsInt("OTP_LENGTH", 6),
		},
		App: AppConfig{
			Name:        "Gidekmi API",
			Version:     "1.0.0",
			Description: "Gidekmi Mobile Application Backend API",
		},
	}

	// Validate configuration
	validateConfig(config)

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getSSLMode(isProduction bool) string {
	if isProduction {
		return "require"
	}
	return getEnv("DB_SSLMODE", "disable")
}

func getCORSOrigins(isProduction bool, baseURL string) []string {
	origins := []string{
		"http://localhost:3000",
		"http://localhost:5173",
		"https://localhost:3000",
		"https://localhost:5173",
	}

	if isProduction {
		// Add production domains
		origins = append(origins,
			baseURL,
			"https://gidekmi.com",
			"https://www.gidekmi.com",
			"https://app.gidekmi.com",
			"https://api.gidekmi.com",
		)
	}

	// Add custom origins from environment
	customOrigins := getEnv("ALLOWED_ORIGINS", "")
	if customOrigins != "" {
		origins = append(origins, parseCommaSeparated(customOrigins)...)
	}

	return origins
}

func getTrustedIPs(isProduction bool) []string {
	// Production'da tüm IP'lere izin ver
	if isProduction {
		return []string{"*"}
	}

	// Development'da belirli IP'lere izin ver
	trustedIPs := getEnv("TRUSTED_IPS", "")
	if trustedIPs != "" {
		return parseCommaSeparated(trustedIPs)
	}

	// Default: tüm IP'lere izin ver (development)
	return []string{"*"}
}

func getGoogleRedirectURL(baseURL string) string {
	customURL := getEnv("GOOGLE_REDIRECT_URL", "")
	if customURL != "" {
		return customURL
	}
	return baseURL + "/api/v1/auth/google/callback"
}

func parseCommaSeparated(str string) []string {
	var result []string
	for _, item := range strings.Split(str, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func validateConfig(cfg *Config) {
	// JWT Secret validation
	if cfg.JWT.Secret == "your_super_secret_jwt_key_here_change_in_production" && cfg.Server.Env == "production" {
		log.Fatal("⚠️  JWT_SECRET must be changed in production!")
	}

	// Email configuration warning
	if cfg.Server.Env == "production" && cfg.Email.SMTPUser == "" {
		log.Println("⚠️  SMTP_USER not configured - email services will not work")
	}

	// Base URL validation
	if cfg.Server.Env == "production" && strings.Contains(cfg.Server.BaseURL, "localhost") {
		log.Println("⚠️  BASE_URL contains localhost in production environment")
	}

	log.Printf("✅ Config loaded for environment: %s", cfg.Server.Env)
	log.Printf("🚀 Server will start on port: %s", cfg.Server.Port)
	log.Printf("🌐 Base URL: %s", cfg.Server.BaseURL)
}
