// Command seed creates the single system-admin. It is the only way to create
// one, and it leaves an existing system-admin unchanged.
package main

import (
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"rbac-platform/gateway/internal/users"
)

func main() {
	dsn := os.Getenv("DATABASE_DSN")
	email := strings.ToLower(os.Getenv("SYSTEM_ADMIN_EMAIL"))
	password := os.Getenv("SYSTEM_ADMIN_PASSWORD")
	if dsn == "" || email == "" || password == "" {
		log.Fatal("DATABASE_DSN, SYSTEM_ADMIN_EMAIL and SYSTEM_ADMIN_PASSWORD are required")
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	var existing int64
	if err := db.Model(&users.User{}).Where("role = ?", users.SystemAdminRole).Count(&existing).Error; err != nil {
		log.Fatalf("check existing system-admin: %v", err)
	}
	if existing > 0 {
		log.Print("system-admin already exists; nothing changed")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}
	admin := users.User{
		Email:        email,
		PasswordHash: string(hash),
		Name:         "System Admin",
		Role:         users.SystemAdminRole,
		IsActive:     true,
	}
	if err := db.Create(&admin).Error; err != nil {
		log.Fatalf("create system-admin: %v", err)
	}
	log.Printf("created system-admin %s", email)
}
