//nolint
package routes

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// Tests of the middlewares replacing the ones embedded in the previous framework

func TestLogger(t *testing.T) {
	buf := new(bytes.Buffer)
	e := echo.New()
	e.Use(logger(buf))
	e.GET("/ok", func(c echo.Context) error { return c.String(200, "ok") })
	e.GET("/fail", func(c echo.Context) error { return echo.NewHTTPError(500, "boom") })

	req, _ := http.NewRequest("GET", "/ok?first=1&second=2", nil)
	req.RemoteAddr = "10.1.2.3:5678"
	req.Header.Set("User-Agent", "test-agent")
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code, "http GET success")
	re := regexp.MustCompile(`^10\.1\.2\.3 - \[\S+\] "GET /ok\?first=1&second=2 HTTP/1\.1" 200 "test-agent" \n$`)
	assert.Equal(t, true, re.MatchString(buf.String()), "log line: "+buf.String())

	buf.Reset()
	req, _ = http.NewRequest("GET", "/fail", nil)
	req.RemoteAddr = "10.1.2.3:5678"
	resp = httptest.NewRecorder()
	e.ServeHTTP(resp, req)

	assert.Equal(t, 500, resp.Code, "http GET error")
	assert.Equal(t, true, regexp.MustCompile(`"GET /fail HTTP/1\.1" 500 ""`).MatchString(buf.String()), "log status: "+buf.String())
	assert.Equal(t, true, regexp.MustCompile(`message=boom\n$`).MatchString(buf.String()), "log error: "+buf.String())
}

func TestTrustedProxies(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5678"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")

	assert.Equal(t, "10.1.2.3", trustedProxies(nil)(req), "no trusted proxy")
	assert.Equal(t, "10.1.2.3", trustedProxies([]string{})(req), "empty trusted proxies")
	assert.Equal(t, "9.9.9.9", trustedProxies([]string{"10.1.2.0/24"})(req), "trusted network")
	assert.Equal(t, "9.9.9.9", trustedProxies([]string{"10.1.2.3"})(req), "trusted ip")
	assert.Equal(t, "10.1.2.3", trustedProxies([]string{"10.9.9.0/24"})(req), "untrusted proxy")
	assert.Equal(t, "10.1.2.3", trustedProxies([]string{"10.1.2.0/24", "bad"})(req), "invalid trusted proxies")

	req6, _ := http.NewRequest("GET", "/", nil)
	req6.RemoteAddr = "[::1]:5678"
	req6.Header.Set("X-Forwarded-For", "9.9.9.9")
	assert.Equal(t, "9.9.9.9", trustedProxies([]string{"::1"})(req6), "trusted ipv6")
	assert.Equal(t, "::1", trustedProxies(nil)(req6), "no trusted ipv6")
}

func TestParseCIDR(t *testing.T) {
	ipRange, err := parseCIDR("10.1.2.0/24")
	assert.Equal(t, nil, err, "valid network")
	assert.Equal(t, "10.1.2.0/24", ipRange.String(), "valid network")

	ipRange, err = parseCIDR("10.1.2.3")
	assert.Equal(t, nil, err, "valid ip")
	assert.Equal(t, "10.1.2.3/32", ipRange.String(), "single ipv4")

	ipRange, err = parseCIDR("::1")
	assert.Equal(t, nil, err, "valid ipv6")
	assert.Equal(t, "::1/128", ipRange.String(), "single ipv6")

	_, err = parseCIDR("bad")
	assert.Equal(t, "invalid ip address: bad", err.Error(), "invalid ip")

	_, err = parseCIDR("10.1.2.0/bad")
	assert.Equal(t, true, err != nil, "invalid network")
}

func TestTrailingSlash(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = redirectTrailingSlash(e)
	e.Pre(removeTrailingSlash(e, "/"))
	e.GET("/list/", func(c echo.Context) error { return c.String(200, "list") })
	e.POST("/save", func(c echo.Context) error { return c.String(200, "save") })
	e.GET("/item/:id", func(c echo.Context) error { return c.String(200, "id="+c.Param("id")) })

	tests := []struct {
		method   string
		url      string
		code     int
		location string
		body     string
	}{
		{"GET", "/list/", 200, "", "list"},                 // declared with its trailing slash
		{"GET", "/list", 301, "/list/", ""},                // declared with a trailing slash
		{"GET", "/list?page=2", 301, "/list/?page=2", ""},  // query string kept
		{"POST", "/save", 200, "", "save"},                 // declared without trailing slash
		{"POST", "/save/", 307, "/save", ""},               // method kept on redirect
		{"GET", "/item/7", 200, "", "id=7"},                // path parameter
		{"GET", "/item/7/", 301, "/item/7", ""},            // trailing slash is not part of the parameter
		{"GET", "/item/7/?page=2", 301, "/item/7?page=2", ""},
		{"GET", "/save", 405, "", ""},     // declared for POST only
		{"GET", "/unknown", 404, "", ""},  // no route
		{"GET", "/unknown/", 301, "/unknown", ""},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, tt.url, nil)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, tt.code, resp.Code, tt.method+" "+tt.url)
		assert.Equal(t, tt.location, resp.Header().Get("Location"), tt.method+" "+tt.url)
		if tt.body != "" {
			assert.Equal(t, tt.body, resp.Body.String(), tt.method+" "+tt.url)
		}
	}
}

func TestHasRoute(t *testing.T) {
	e := echo.New()
	e.GET("/list/", func(c echo.Context) error { return nil })
	e.POST("/save", func(c echo.Context) error { return nil })

	assert.Equal(t, true, hasRoute(e, "GET", "/list/"), "declared route")
	assert.Equal(t, true, hasRoute(e, "", "/list/"), "any method")
	assert.Equal(t, false, hasRoute(e, "POST", "/list/"), "other method")
	assert.Equal(t, false, hasRoute(e, "", "/list"), "other path")
}

func TestServeStatic(t *testing.T) {
	e := echo.New()
	e.Use(serveStatic("/", EmbedFolder(server, "web/assets")))
	e.GET("/*", func(c echo.Context) error { return c.String(404, "no file") })

	tests := []struct {
		url  string
		code int
		body string
	}{
		{"/favicon.ico", 200, ""},
		{"/css/bootstrap-icons.css", 200, ""},
		{"/", 404, "no file"},     // directories are not served
		{"/css/", 404, "no file"}, // directories are not served
		{"/unknown.css", 404, "no file"},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", tt.url, nil)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, tt.code, resp.Code, tt.url)
		if tt.body != "" {
			assert.Equal(t, tt.body, resp.Body.String(), tt.url)
		} else {
			assert.Equal(t, true, resp.Body.Len() > 0, tt.url)
		}
	}

	assert.Panics(t, func() { EmbedFolder(server, "../web/assets") }, "unknown embedded folder")
}

func TestSslHeaders(t *testing.T) {
	e := echo.New()
	e.Use(sslHeaders("secure.example.com"))
	e.GET("/auth/login", func(c echo.Context) error { return c.String(200, "login") })

	req, _ := http.NewRequest("GET", "/auth/login", nil)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, 301, resp.Code, "http redirected to https")
	assert.Equal(t, "https://secure.example.com/auth/login", resp.Header().Get("Location"), "redirect to ssl host")

	req, _ = http.NewRequest("GET", "/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp = httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code, "https success")
	assert.Equal(t, "max-age=315360000; includeSubDomains", resp.Header().Get("Strict-Transport-Security"), "sts header")
}
