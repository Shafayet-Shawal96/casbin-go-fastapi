// Package auth issues and validates JWTs and handles login.
package auth

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"rbac-platform/gateway/internal/users"
)

const (
	tokenTTL   = time.Hour
	contextKey = "auth.user"
)

// dummyHash is compared when the email is unknown, so that response time does
// not reveal whether an account exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)

type Service struct {
	Secret []byte
	Users  users.Store
}

func (s Service) Issue(userID int64) (string, time.Time, error) {
	expires := time.Now().Add(tokenTTL)
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		ExpiresAt: jwt.NewNumericDate(expires),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	return token, expires, err
}

func (s Service) parse(raw string) (int64, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return s.Secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(claims.Subject, 10, 64)
}

type loginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s Service) Login(c *gin.Context) {
	var body loginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "email and password are required"})
		return
	}

	user, err := s.Users.ByEmail(c.Request.Context(), strings.ToLower(body.Email))
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "login failed"})
		return
	}
	hash := []byte(user.PasswordHash)
	if err != nil {
		hash = dummyHash
	}
	passwordErr := bcrypt.CompareHashAndPassword(hash, []byte(body.Password))
	if err != nil || passwordErr != nil || !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "invalid email or password"})
		return
	}

	token, expires, err := s.Issue(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "login failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "expires_at": expires.UTC()})
}

// Middleware authenticates the bearer token and loads the current role and
// status from the database, so role changes and deactivation apply immediately.
func (s Service) Middleware(c *gin.Context) {
	raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}
	id, err := s.parse(raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid token"})
		return
	}
	user, err := s.Users.ByID(c.Request.Context(), id)
	if errors.Is(err, users.ErrNotFound) || (err == nil && !user.IsActive) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "account is not active"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "could not load user"})
		return
	}
	c.Set(contextKey, user)
	c.Next()
}

// Actor returns the authenticated user set by Middleware.
func Actor(c *gin.Context) users.User {
	return c.MustGet(contextKey).(users.User)
}
