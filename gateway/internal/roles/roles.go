// Package roles implements createRole and role listing.
package roles

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"rbac-platform/gateway/internal/rbac"
	"rbac-platform/gateway/internal/users"
)

const maxBodyBytes = 1 << 16

var (
	ErrExists   = errors.New("role already exists")
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
)

type Role struct {
	Name      string `gorm:"primaryKey"`
	IsBuiltin bool
}

type Repo interface {
	List(ctx context.Context) ([]Role, error)
	Create(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
}

type GormRepo struct {
	DB *gorm.DB
}

func (r GormRepo) List(ctx context.Context) ([]Role, error) {
	var out []Role
	err := r.DB.WithContext(ctx).Order("name").Find(&out).Error
	return out, err
}

func (r GormRepo) Create(ctx context.Context, name string) error {
	err := r.DB.WithContext(ctx).Create(&Role{Name: name}).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrExists
	}
	return err
}

func (r GormRepo) Delete(ctx context.Context, name string) error {
	return r.DB.WithContext(ctx).Delete(&Role{Name: name}).Error
}

type Handler struct {
	Repo     Repo
	Enforcer *rbac.Enforcer
}

type roleOut struct {
	Name       string `json:"name"`
	IsBuiltin  bool   `json:"is_builtin"`
	Assignable bool   `json:"assignable"`
}

// List returns all roles and the permissions a custom role may be given.
func (h Handler) List(c *gin.Context) {
	found, err := h.Repo.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "could not list roles"})
		return
	}
	out := make([]roleOut, 0, len(found))
	for _, role := range found {
		out = append(out, roleOut{role.Name, role.IsBuiltin, role.Name != users.SystemAdminRole})
	}
	c.JSON(http.StatusOK, gin.H{"roles": out, "grantable": rbac.Grantable})
}

type createRequest struct {
	Name        string            `json:"name"`
	Permissions []rbac.Permission `json:"permissions"`
}

// Create adds a custom role with permissions from the grantable list.
func (h Handler) Create(c *gin.Context) {
	var body createRequest
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": "invalid request body"})
		return
	}
	if !namePattern.MatchString(body.Name) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"detail": "name must be 2-64 characters: lowercase letters, digits and hyphens, starting with a letter",
		})
		return
	}
	permissions, ok := validPermissions(body.Permissions)
	if !ok {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"detail": "permissions must be a non-empty list of grantable permissions",
		})
		return
	}

	ctx := c.Request.Context()
	if err := h.Repo.Create(ctx, body.Name); err != nil {
		if errors.Is(err, ErrExists) {
			c.JSON(http.StatusConflict, gin.H{"detail": "role already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "could not create role"})
		return
	}
	if err := h.Enforcer.AddRole(body.Name, permissions); err != nil {
		if deleteErr := h.Repo.Delete(context.WithoutCancel(ctx), body.Name); deleteErr != nil {
			log.Printf("could not remove role %q after policy failure: %v", body.Name, deleteErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "could not create role"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"name": body.Name, "permissions": permissions})
}

// validPermissions removes duplicates and rejects anything not grantable.
func validPermissions(requested []rbac.Permission) ([]rbac.Permission, bool) {
	seen := make(map[rbac.Permission]bool, len(requested))
	out := make([]rbac.Permission, 0, len(requested))
	for _, p := range requested {
		if !rbac.IsGrantable(p) {
			return nil, false
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	// Every signed-in user needs /me, which the UI uses to load the session.
	readMe := rbac.Permission{Obj: "me", Act: "read", Scope: rbac.ScopeAny}
	if !seen[readMe] {
		out = append(out, readMe)
	}
	return out, true
}
