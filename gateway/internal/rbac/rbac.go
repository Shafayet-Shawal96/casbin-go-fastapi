// Package rbac wraps the Casbin enforcer and defines the built-in policies.
package rbac

import (
	_ "embed"
	"net/http"
	"strconv"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/gin-gonic/gin"

	"rbac-platform/gateway/internal/auth"
)

//go:embed model.conf
var modelText string

const (
	ScopeAny = "any"
	ScopeOwn = "own"
)

type Permission struct {
	Obj   string `json:"obj"`
	Act   string `json:"act"`
	Scope string `json:"scope"`
}

var (
	listUsers   = Permission{"users", "list", ScopeAny}
	readUser    = Permission{"users", "read", ScopeAny}
	readMe      = Permission{"me", "read", ScopeAny}
	infoAny     = Permission{"user_info", "update", ScopeAny}
	infoOwn     = Permission{"user_info", "update", ScopeOwn}
	companyAny  = Permission{"company_info", "update", ScopeAny}
	companyOwn  = Permission{"company_info", "update", ScopeOwn}
	deactivate  = Permission{"users", "deactivate", ScopeAny}
	createUser  = Permission{"users", "create", ScopeAny}
	assignRole  = Permission{"user_role", "assign", ScopeAny}
	createRole  = Permission{"roles", "create", ScopeAny}
	listRoles   = Permission{"roles", "list", ScopeAny}
	management  = []Permission{createUser, assignRole, createRole, listRoles}
	superAdmin  = append([]Permission{listUsers, readUser, readMe, infoAny, companyAny}, management...)
	systemAdmin = append(append([]Permission{}, superAdmin...), deactivate)
)

// Builtin is the default policy for each built-in role.
var Builtin = map[string][]Permission{
	"system-admin": systemAdmin,
	"super-admin":  superAdmin,
	"admin":        {listUsers, readUser, readMe, companyAny},
	"user":         {readMe, infoOwn},
}

// Grantable lists what createRole may give a custom role. Deactivation and role
// management are excluded so a super-admin cannot use a new role to gain them.
var Grantable = []Permission{listUsers, readUser, readMe, infoAny, infoOwn, companyAny, companyOwn}

// IsGrantable reports whether a permission may be given to a custom role.
func IsGrantable(p Permission) bool {
	for _, allowed := range Grantable {
		if p == allowed {
			return true
		}
	}
	return false
}

type Enforcer struct {
	inner *casbin.SyncedEnforcer
}

// New creates an enforcer. A nil adapter keeps policies in memory, for tests.
func New(adapter persist.Adapter) (*Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, err
	}
	var inner *casbin.SyncedEnforcer
	if adapter == nil {
		inner, err = casbin.NewSyncedEnforcer(m)
	} else {
		inner, err = casbin.NewSyncedEnforcer(m, adapter)
	}
	if err != nil {
		return nil, err
	}
	return &Enforcer{inner: inner}, nil
}

// SeedIfEmpty adds built-in policies only to an empty table, so runtime changes
// survive restarts.
func (e *Enforcer) SeedIfEmpty() error {
	existing, err := e.inner.GetPolicy()
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	for role, permissions := range Builtin {
		if err := e.AddRole(role, permissions); err != nil {
			return err
		}
	}
	return nil
}

// AddRole stores a role's permissions in the adapter and in memory.
func (e *Enforcer) AddRole(role string, permissions []Permission) error {
	rows := make([][]string, 0, len(permissions))
	for _, p := range permissions {
		rows = append(rows, []string{role, p.Obj, p.Act, p.Scope})
	}
	_, err := e.inner.AddPolicies(rows)
	return err
}

// Permissions returns the permissions held by a role.
func (e *Enforcer) Permissions(role string) ([]Permission, error) {
	rows, err := e.inner.GetFilteredPolicy(0, role)
	if err != nil {
		return nil, err
	}
	permissions := make([]Permission, 0, len(rows))
	for _, row := range rows {
		permissions = append(permissions, Permission{row[1], row[2], row[3]})
	}
	return permissions, nil
}

// Require allows the request only if Casbin grants obj/act to the actor's role.
// The target is the :id route parameter, used for "own" scoped policies.
func (e *Enforcer) Require(obj, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor := auth.Actor(c)
		allowed, err := e.inner.Enforce(actor.Role, obj, act, strconv.FormatInt(actor.ID, 10), c.Param("id"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "authorization failed"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "forbidden"})
			return
		}
		c.Next()
	}
}
