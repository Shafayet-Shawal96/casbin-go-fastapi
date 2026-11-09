// Package guards holds checks that depend on the target user, which Casbin's
// role policies cannot express.
package guards

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"rbac-platform/gateway/internal/auth"
	"rbac-platform/gateway/internal/users"
)

func targetID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"detail": "invalid user id"})
		return 0, false
	}
	return id, true
}

// ProtectSystemAdmin lets only a system-admin modify a system-admin.
func ProtectSystemAdmin(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := targetID(c)
		if !ok {
			return
		}
		target, err := store.ByID(c.Request.Context(), id)
		if errors.Is(err, users.ErrNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"detail": "user not found"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "could not load user"})
			return
		}
		if target.Role == users.SystemAdminRole && auth.Actor(c).Role != users.SystemAdminRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "cannot modify a system-admin"})
			return
		}
		c.Next()
	}
}

// NoSelfDeactivate stops users from deactivating their own account.
func NoSelfDeactivate(c *gin.Context) {
	id, ok := targetID(c)
	if !ok {
		return
	}
	if id == auth.Actor(c).ID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "cannot deactivate yourself"})
		return
	}
	c.Next()
}
