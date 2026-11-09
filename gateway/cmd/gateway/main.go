package main

import (
	"log"
	"net/http"
	"time"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"rbac-platform/gateway/internal/auth"
	"rbac-platform/gateway/internal/config"
	"rbac-platform/gateway/internal/proxy"
	"rbac-platform/gateway/internal/rbac"
	"rbac-platform/gateway/internal/roles"
	"rbac-platform/gateway/internal/server"
	"rbac-platform/gateway/internal/users"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	db, err := gorm.Open(mysql.Open(cfg.DatabaseDSN), &gorm.Config{TranslateError: true})
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		log.Fatalf("casbin adapter: %v", err)
	}
	enforcer, err := rbac.New(adapter)
	if err != nil {
		log.Fatalf("casbin enforcer: %v", err)
	}
	if err := enforcer.SeedIfEmpty(); err != nil {
		log.Fatalf("seed policies: %v", err)
	}
	upstream, err := proxy.New(cfg.UpstreamURL, cfg.InternalToken, enforcer)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	store := users.GormStore{DB: db}
	router := server.NewRouter(server.Deps{
		Auth:     auth.Service{Secret: []byte(cfg.JWTSecret), Users: store},
		Enforcer: enforcer,
		Proxy:    upstream,
		Users:    store,
		Roles:    roles.Handler{Repo: roles.GormRepo{DB: db}, Enforcer: enforcer},
	})

	srv := &http.Server{Addr: ":" + cfg.Port, Handler: router, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("gateway listening on :%s", cfg.Port)
	log.Fatal(srv.ListenAndServe())
}
