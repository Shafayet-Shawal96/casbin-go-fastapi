package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"rbac-platform/gateway/internal/auth"
	"rbac-platform/gateway/internal/proxy"
	"rbac-platform/gateway/internal/rbac"
	"rbac-platform/gateway/internal/roles"
	"rbac-platform/gateway/internal/users"
)

const (
	sysAdminID int64 = 1
	superID    int64 = 2
	adminID    int64 = 3
	userID     int64 = 4
	otherID    int64 = 5
	inactiveID int64 = 6
	password         = "correct-password"
)

type fakeUsers map[int64]users.User

func (f fakeUsers) ByID(_ context.Context, id int64) (users.User, error) {
	if u, ok := f[id]; ok {
		return u, nil
	}
	return users.User{}, users.ErrNotFound
}

func (f fakeUsers) ByEmail(_ context.Context, email string) (users.User, error) {
	for _, u := range f {
		if u.Email == email {
			return u, nil
		}
	}
	return users.User{}, users.ErrNotFound
}

type fakeRoles map[string]bool

func (f fakeRoles) List(context.Context) ([]roles.Role, error) { return nil, nil }

func (f fakeRoles) Create(_ context.Context, name string) error {
	if f[name] {
		return roles.ErrExists
	}
	f[name] = true
	return nil
}

func (f fakeRoles) Delete(_ context.Context, name string) error {
	delete(f, name)
	return nil
}

type harness struct {
	t         *testing.T
	router    http.Handler
	auth      auth.Service
	users     fakeUsers
	upstream  *http.Header
	upstreamN *int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	make1 := func(id int64, role string, active bool) users.User {
		return users.User{ID: id, Email: fmt.Sprintf("u%d@x.io", id), PasswordHash: string(hash), Role: role, IsActive: active}
	}
	store := fakeUsers{
		sysAdminID: make1(sysAdminID, "system-admin", true),
		superID:    make1(superID, "super-admin", true),
		adminID:    make1(adminID, "admin", true),
		userID:     make1(userID, "user", true),
		otherID:    make1(otherID, "user", true),
		inactiveID: make1(inactiveID, "system-admin", false),
	}

	var lastHeader http.Header
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastHeader = r.Header.Clone()
		calls++
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	}))
	t.Cleanup(upstream.Close)

	enforcer, err := rbac.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcer.SeedIfEmpty(); err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(upstream.URL, "internal", enforcer)
	if err != nil {
		t.Fatal(err)
	}
	service := auth.Service{Secret: []byte("test-secret-test-secret"), Users: store}
	router := NewRouter(Deps{
		Auth:     service,
		Enforcer: enforcer,
		Proxy:    p,
		Users:    store,
		Roles:    roles.Handler{Repo: fakeRoles{"admin": true}, Enforcer: enforcer},
	})
	return &harness{t: t, router: router, auth: service, users: store, upstream: &lastHeader, upstreamN: &calls}
}

// recorder adds CloseNotify, which Gin's writer requires when proxying.
type recorder struct {
	*httptest.ResponseRecorder
}

func (recorder) CloseNotify() <-chan bool { return make(chan bool) }

func newRecorder() recorder {
	return recorder{httptest.NewRecorder()}
}

func (h *harness) do(actor int64, method, path, body string) recorder {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if actor != 0 {
		token, _, err := h.auth.Issue(actor)
		if err != nil {
			h.t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := newRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func TestPermissionMatrix(t *testing.T) {
	validRole := `{"name":"auditor","permissions":[{"obj":"users","act":"list","scope":"any"}]}`
	type route struct {
		name, method, path, body string
		// expected status for system-admin, super-admin, admin, user
		want [4]int
	}
	const ok, no = 200, 403
	routes := []route{
		{"getallusers", "GET", "/api/users", "", [4]int{ok, ok, ok, no}},
		{"getuser", "GET", "/api/users/5", "", [4]int{ok, ok, ok, no}},
		{"me", "GET", "/api/me", "", [4]int{ok, ok, ok, ok}},
		{"updateuserinfo", "PATCH", "/api/users/5/info", "{}", [4]int{ok, ok, no, no}},
		{"updatecompany", "PATCH", "/api/users/5/company", "{}", [4]int{ok, ok, ok, no}},
		{"deactivate", "POST", "/api/users/5/deactivate", "", [4]int{ok, no, no, no}},
		{"createuser", "POST", "/api/users", "{}", [4]int{ok, ok, no, no}},
		{"assignrole", "PUT", "/api/users/5/role", "{}", [4]int{ok, ok, no, no}},
		{"listroles", "GET", "/api/roles", "", [4]int{ok, ok, no, no}},
		{"createrole", "POST", "/api/roles", validRole, [4]int{201, 409, no, no}},
	}
	actors := [4]int64{sysAdminID, superID, adminID, userID}

	h := newHarness(t)
	for _, r := range routes {
		for i, actor := range actors {
			t.Run(fmt.Sprintf("%s/%d", r.name, actor), func(t *testing.T) {
				rec := h.do(actor, r.method, r.path, r.body)
				if rec.Code != r.want[i] {
					t.Fatalf("got %d, want %d: %s", rec.Code, r.want[i], rec.Body.String())
				}
			})
		}
	}
}

func TestOwnScope(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(userID, "PATCH", "/api/users/4/info", "{}"); rec.Code != 200 {
		t.Fatalf("own update: got %d", rec.Code)
	}
	if rec := h.do(userID, "PATCH", "/api/users/5/info", "{}"); rec.Code != 403 {
		t.Fatalf("other update: got %d", rec.Code)
	}
	if rec := h.do(userID, "PATCH", "/api/users/04/info", "{}"); rec.Code != 403 {
		t.Fatalf("alternate id form: got %d", rec.Code)
	}
	if rec := h.do(userID, "PATCH", "/api/users/4/company", "{}"); rec.Code != 403 {
		t.Fatalf("own company: got %d", rec.Code)
	}
}

func TestGuards(t *testing.T) {
	tests := []struct {
		name         string
		actor        int64
		method, path string
		want         int
	}{
		{"super cannot edit system-admin info", superID, "PATCH", "/api/users/1/info", 403},
		{"super cannot edit system-admin company", superID, "PATCH", "/api/users/1/company", 403},
		{"admin cannot edit system-admin company", adminID, "PATCH", "/api/users/1/company", 403},
		{"alternate id form is still guarded", superID, "PATCH", "/api/users/01/info", 403},
		{"system-admin can edit self", sysAdminID, "PATCH", "/api/users/1/info", 200},
		{"system-admin cannot deactivate self", sysAdminID, "POST", "/api/users/1/deactivate", 403},
		{"alternate id cannot bypass self check", sysAdminID, "POST", "/api/users/01/deactivate", 403},
		{"missing target", superID, "PATCH", "/api/users/99/info", 404},
		{"invalid id", superID, "PATCH", "/api/users/abc/info", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			if rec := h.do(tt.actor, tt.method, tt.path, "{}"); rec.Code != tt.want {
				t.Fatalf("got %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestAuthentication(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(0, "GET", "/api/me", ""); rec.Code != 401 {
		t.Fatalf("no token: got %d", rec.Code)
	}
	if rec := h.do(inactiveID, "GET", "/api/me", ""); rec.Code != 401 {
		t.Fatalf("inactive: got %d", rec.Code)
	}

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	rec := newRecorder()
	h.router.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("bad token: got %d", rec.Code)
	}
}

func TestDeactivationAppliesToExistingToken(t *testing.T) {
	h := newHarness(t)
	u := h.users[userID]
	u.IsActive = false
	h.users[userID] = u
	if rec := h.do(userID, "GET", "/api/me", ""); rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name, email, password string
		want                  int
	}{
		{"valid", "u4@x.io", password, 200},
		{"email is case-insensitive", "U4@X.IO", password, 200},
		{"wrong password", "u4@x.io", "nope", 401},
		{"unknown email", "none@x.io", password, 401},
		{"inactive", "u6@x.io", password, 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			body := fmt.Sprintf(`{"email":%q,"password":%q}`, tt.email, tt.password)
			if rec := h.do(0, "POST", "/auth/login", body); rec.Code != tt.want {
				t.Fatalf("got %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestProxyReplacesClientIdentityHeaders(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("GET", "/api/me", nil)
	token, _, _ := h.auth.Issue(userID)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Role", "system-admin")
	req.Header.Set("X-User-Extra", "spoof")
	req.Header.Set("X-Internal-Token", "spoof")
	rec := newRecorder()
	h.router.ServeHTTP(rec, req)

	got := *h.upstream
	if got.Get("X-User-Id") != "4" || got.Get("X-User-Role") != "user" || got.Get("X-Internal-Token") != "internal" {
		t.Fatalf("headers not replaced: %v", got)
	}
	if got.Get("X-User-Extra") != "" || got.Get("Authorization") != "" {
		t.Fatalf("client headers leaked: %v", got)
	}
}

func TestMeIncludesPermissions(t *testing.T) {
	h := newHarness(t)
	rec := h.do(userID, "GET", "/api/me", "")
	var body struct {
		Path        string            `json:"path"`
		Permissions []rbac.Permission `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if body.Path != "/me" || len(body.Permissions) != 2 {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestCreateRole(t *testing.T) {
	perm := func(obj, act, scope string) string {
		return fmt.Sprintf(`{"name":"auditor","permissions":[{"obj":%q,"act":%q,"scope":%q}]}`, obj, act, scope)
	}
	tests := []struct {
		name, body string
		want       int
	}{
		{"grantable", perm("users", "read", "any"), 201},
		{"deactivate is not grantable", perm("users", "deactivate", "any"), 422},
		{"create user is not grantable", perm("users", "create", "any"), 422},
		{"assign role is not grantable", perm("user_role", "assign", "any"), 422},
		{"create role is not grantable", perm("roles", "create", "any"), 422},
		{"list roles is not grantable", perm("roles", "list", "any"), 422},
		{"own scope not valid for list", perm("users", "list", "own"), 422},
		{"empty permissions", `{"name":"auditor","permissions":[]}`, 422},
		{"existing name", `{"name":"admin","permissions":[{"obj":"users","act":"read","scope":"any"}]}`, 409},
		{"invalid name", `{"name":"Bad Name","permissions":[{"obj":"users","act":"read","scope":"any"}]}`, 422},
		{"unknown field", `{"name":"auditor","extra":1,"permissions":[{"obj":"users","act":"read","scope":"any"}]}`, 422},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			if rec := h.do(superID, "POST", "/api/roles", tt.body); rec.Code != tt.want {
				t.Fatalf("got %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestCustomRoleAppliesImmediately(t *testing.T) {
	h := newHarness(t)
	body := `{"name":"auditor","permissions":[{"obj":"users","act":"list","scope":"any"}]}`
	if rec := h.do(superID, "POST", "/api/roles", body); rec.Code != 201 {
		t.Fatalf("create: got %d", rec.Code)
	}
	u := h.users[otherID]
	u.Role = "auditor"
	h.users[otherID] = u
	if rec := h.do(otherID, "GET", "/api/users", ""); rec.Code != 200 {
		t.Fatalf("granted route: got %d", rec.Code)
	}
	if rec := h.do(otherID, "GET", "/api/users/4", ""); rec.Code != 403 {
		t.Fatalf("ungranted route: got %d", rec.Code)
	}
	if rec := h.do(otherID, "GET", "/api/me", ""); rec.Code != 200 {
		t.Fatalf("custom roles always get /me: got %d", rec.Code)
	}
}

func TestDeniedRequestsDoNotReachUpstream(t *testing.T) {
	h := newHarness(t)
	h.do(userID, "GET", "/api/users", "")
	if *h.upstreamN != 0 {
		t.Fatalf("upstream called %d times", *h.upstreamN)
	}
}
