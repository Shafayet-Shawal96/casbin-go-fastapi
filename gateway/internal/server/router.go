// Package server wires the gateway's routes.
package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"rbac-platform/gateway/internal/auth"
	"rbac-platform/gateway/internal/guards"
	"rbac-platform/gateway/internal/proxy"
	"rbac-platform/gateway/internal/rbac"
	"rbac-platform/gateway/internal/roles"
	"rbac-platform/gateway/internal/users"
)

type Deps struct {
	Auth     auth.Service
	Enforcer *rbac.Enforcer
	Proxy    *proxy.Proxy
	Users    users.Store
	Roles    roles.Handler
}

// NewRouter registers every route. A route with no entry here returns 404, and
// every /api route must declare the Casbin permission it needs.
func NewRouter(d Deps) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	_ = r.SetTrustedProxies(nil)
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "not found"})
	})

	r.POST("/auth/login", d.Auth.Login)

	api := r.Group("/api", d.Auth.Middleware)
	can := d.Enforcer.Require
	protect := guards.ProtectSystemAdmin(d.Users)

	api.GET("/me", can("me", "read"), d.Proxy.Me)
	api.GET("/users", can("users", "list"), d.Proxy.Forward)
	api.POST("/users", can("users", "create"), d.Proxy.Forward)
	api.GET("/users/:id", can("users", "read"), d.Proxy.Forward)
	api.PATCH("/users/:id/info", can("user_info", "update"), protect, d.Proxy.Forward)
	api.PATCH("/users/:id/company", can("company_info", "update"), protect, d.Proxy.Forward)
	api.POST("/users/:id/deactivate", can("users", "deactivate"), guards.NoSelfDeactivate, d.Proxy.Forward)
	api.PUT("/users/:id/role", can("user_role", "assign"), d.Proxy.Forward)
	api.GET("/roles", can("roles", "list"), d.Roles.List)
	api.POST("/roles", can("roles", "create"), d.Roles.Create)

	return r
}
