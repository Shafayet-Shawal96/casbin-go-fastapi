// Package proxy forwards authorized requests to the FastAPI service.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"rbac-platform/gateway/internal/auth"
	"rbac-platform/gateway/internal/rbac"
)

const apiPrefix = "/api"

type Proxy struct {
	token   string
	forward *httputil.ReverseProxy
	me      *httputil.ReverseProxy
}

func New(upstream string, token string, enforcer *rbac.Enforcer) (*Proxy, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream url: %w", err)
	}
	me := newReverseProxy(target)
	me.ModifyResponse = addPermissions(enforcer)
	return &Proxy{token: token, forward: newReverseProxy(target), me: me}, nil
}

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, apiPrefix)
			r.Out.URL.RawPath = ""
			r.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"detail":"upstream unavailable"}`))
		},
	}
}

// setTrustedHeaders removes identity headers sent by the client and replaces
// them with values from the authenticated user.
func (p *Proxy) setTrustedHeaders(c *gin.Context) {
	header := c.Request.Header
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-user-") {
			header.Del(name)
		}
	}
	header.Del("Authorization")
	header.Del("Cookie")
	actor := auth.Actor(c)
	header.Set("X-User-Id", strconv.FormatInt(actor.ID, 10))
	header.Set("X-User-Role", actor.Role)
	header.Set("X-Internal-Token", p.token)
}

// Forward proxies the request to FastAPI.
func (p *Proxy) Forward(c *gin.Context) {
	p.setTrustedHeaders(c)
	p.forward.ServeHTTP(c.Writer, c.Request)
}

// Me proxies /me and adds the caller's Casbin permissions to the response.
func (p *Proxy) Me(c *gin.Context) {
	p.setTrustedHeaders(c)
	c.Request.Header.Del("Accept-Encoding")
	p.me.ServeHTTP(c.Writer, c.Request)
}

func addPermissions(enforcer *rbac.Enforcer) func(*http.Response) error {
	return func(res *http.Response) error {
		if res.StatusCode != http.StatusOK {
			return nil
		}
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		_ = res.Body.Close()

		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		permissions, err := enforcer.Permissions(res.Request.Header.Get("X-User-Role"))
		if err != nil {
			return err
		}
		body["permissions"] = permissions

		out, err := json.Marshal(body)
		if err != nil {
			return err
		}
		res.Body = io.NopCloser(bytes.NewReader(out))
		res.ContentLength = int64(len(out))
		res.Header.Set("Content-Length", strconv.Itoa(len(out)))
		return nil
	}
}
