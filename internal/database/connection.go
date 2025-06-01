// internal/database/connection.go
package database

import (
	"fmt"
	"log"

	"github.com/gidekmi/backend/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase(cfg *config.Config) *Database {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Europe/Istanbul",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	// GORM config
	gormConfig := &gorm.Config{}

	// Development ortamında SQL loglarını göster
	if cfg.Server.Env == "development" {
		gormConfig.Logger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}

	// Set maximum number of open connections
	sqlDB.SetMaxOpenConns(25)

	// Set maximum number of idle connections
	sqlDB.SetMaxIdleConns(5)

	// Set maximum lifetime of connections
	// sqlDB.SetConnMaxLifetime(5 * time.Minute)

	log.Println("Successfully connected to PostgreSQL database")

	return &Database{DB: db}
}

func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *Database) Migrate(models ...interface{}) error {
	log.Println("Running database migrations...")

	for _, model := range models {
		if err := d.DB.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate model %T: %w", model, err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}
