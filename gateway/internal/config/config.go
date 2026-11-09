// Package config loads gateway settings from the environment.
package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseDSN   string
	JWTSecret     string
	InternalToken string
	UpstreamURL   string
	Port          string
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseDSN:   os.Getenv("DATABASE_DSN"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		InternalToken: os.Getenv("INTERNAL_TOKEN"),
		UpstreamURL:   os.Getenv("UPSTREAM_URL"),
		Port:          os.Getenv("PORT"),
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	required := map[string]string{
		"DATABASE_DSN":   cfg.DatabaseDSN,
		"JWT_SECRET":     cfg.JWTSecret,
		"INTERNAL_TOKEN": cfg.InternalToken,
		"UPSTREAM_URL":   cfg.UpstreamURL,
	}
	for name, value := range required {
		if value == "" {
			return Config{}, fmt.Errorf("%s is required", name)
		}
	}
	if len(cfg.JWTSecret) < 16 {
		return Config{}, fmt.Errorf("JWT_SECRET must be at least 16 characters")
	}
	return cfg, nil
}
