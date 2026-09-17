package routes

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/md5" //nolint:gosec // only for cache headers

	"github.com/kataras/i18n"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/unrolled/secure"

	"github.com/ulule/limiter"
	mstdlib "github.com/ulule/limiter/drivers/middleware/stdlib"
	"github.com/ulule/limiter/drivers/store/memory"

	"glauth-ui-light/config"
	. "glauth-ui-light/handlers"
	. "glauth-ui-light/helpers"
)

//go:embed web/assets/*
var server embed.FS

//go:embed web/templates/*
var templateFs embed.FS

// DefaultWriter is the writer used by the logger middleware.
var DefaultWriter io.Writer = os.Stdout

// ServeFileSystem is a file system with an existence check.
type ServeFileSystem interface {
	http.FileSystem
	Exists(prefix string, path string) bool
}

type embedFileSystem struct {
	http.FileSystem
}

func (e embedFileSystem) Exists(prefix string, path string) bool {
	f, err := e.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// only files are served, requests on a directory are not found
	stat, err := f.Stat()
	return err == nil && !stat.IsDir()
}

func EmbedFolder(fsEmbed embed.FS, targetPath string) ServeFileSystem {
	fsys, err := fs.Sub(fsEmbed, targetPath)
	if err != nil {
		panic(err)
	}
	return embedFileSystem{
		FileSystem: http.FS(fsys),
	}
}

// serveStatic serves the files of the given file system, requests without
// matching file are passed to the next handler.
func serveStatic(urlPrefix string, fsys ServeFileSystem) echo.MiddlewareFunc {
	fileserver := http.FileServer(fsys)
	if urlPrefix != "" {
		fileserver = http.StripPrefix(urlPrefix, fileserver)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if fsys.Exists(urlPrefix, c.Request().URL.Path) {
				fileserver.ServeHTTP(c.Response(), c.Request())
				return nil
			}
			return next(c)
		}
	}
}

func setConfig(cfg *config.WebConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("Cfg", *cfg)
			return next(c)
		}
	}
}

func secureHeaders() echo.MiddlewareFunc {
	s := echo.WrapMiddleware(secure.New(secure.Options{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline'; img-src 'self' data:",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}).Handler)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		h := s(next)
		return func(c echo.Context) error {
			// IENoOpen: header not handled by unrolled/secure
			c.Response().Header().Set("X-Download-Options", "noopen")
			return h(c)
		}
	}
}

func sslHeaders(port string) echo.MiddlewareFunc {
	return echo.WrapMiddleware(secure.New(secure.Options{
		SSLRedirect:          true,
		SSLHost:              port,
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
	}).Handler)
}

// logger writes one line per request on the given writer.
func logger(out io.Writer) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			path := req.URL.Path
			raw := req.URL.RawQuery

			errorMessage := ""
			if err := next(c); err != nil {
				c.Error(err)
				errorMessage = err.Error()
			}

			if raw != "" {
				path = path + "?" + raw
			}

			// custom format
			// fmt.Fprintf(out, "%s - [%s] \"%s %s %s\" %d \"%s\" %s\n",
			fmt.Fprintf(out, "%s - [%s] \"%s %s %s\" %d %q %s\n",
				c.RealIP(),
				time.Now().Format(time.RFC3339),
				req.Method,
				path,
				req.Proto,
				c.Response().Status,
				req.UserAgent(),
				errorMessage,
			)
			return nil
		}
	}
}

// trustedProxies returns the extractor giving the source IP of a request:
// the X-Forwarded-For header is only read for requests coming from a trusted proxy.
func trustedProxies(proxies []string) echo.IPExtractor {
	if len(proxies) == 0 {
		return echo.ExtractIPDirect()
	}
	opts := []echo.TrustOption{
		echo.TrustLoopback(false),
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false),
	}
	for _, proxy := range proxies {
		ipRange, err := parseCIDR(proxy)
		if err != nil {
			// no proxy is trusted when one of them is invalid
			return echo.ExtractIPDirect()
		}
		opts = append(opts, echo.TrustIPRange(ipRange))
	}
	return echo.ExtractIPFromXFFHeader(opts...)
}

func parseCIDR(proxy string) (*net.IPNet, error) {
	if !strings.Contains(proxy, "/") {
		ip := net.ParseIP(proxy)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address: %s", proxy)
		}
		suffix := "/32"
		if ip.To4() == nil {
			suffix = "/128"
		}
		proxy += suffix
	}
	_, ipRange, err := net.ParseCIDR(proxy)
	return ipRange, err
}

// hasRoute reports whether a route is declared for this exact path,
// whatever the method when it is empty.
func hasRoute(e *echo.Echo, method string, path string) bool {
	for _, r := range e.Routes() {
		if r.Path == path && (method == "" || r.Method == method) {
			return true
		}
	}
	return false
}

// redirectPath redirects to the given path, keeping the query string.
func redirectPath(c echo.Context, path string) error {
	req := c.Request()
	code := http.StatusMovedPermanently
	if req.Method != http.MethodGet {
		code = http.StatusTemporaryRedirect
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	return c.Redirect(code, path)
}

// removeTrailingSlash redirects the paths of the given prefix to the path
// without their trailing slash, unless a route is declared with it. It runs
// before the router: a trailing slash would otherwise be read as part of the
// last path parameter, ":id/" for example. Static files, served by their own
// routes, are left untouched.
func removeTrailingSlash(e *echo.Echo, prefix string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			p := c.Request().URL.Path
			if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, "/") || hasRoute(e, "", p) {
				return next(c)
			}
			return redirectPath(c, strings.TrimSuffix(p, "/"))
		}
	}
}

// redirectTrailingSlash redirects to the path with a trailing slash when no
// route matches the request path but one exists for this path.
func redirectTrailingSlash(e *echo.Echo) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		he, ok := err.(*echo.HTTPError)
		if ok && he.Code == http.StatusNotFound && !c.Response().Committed {
			req := c.Request()
			if hasRoute(e, req.Method, req.URL.Path+"/") {
				if rerr := redirectPath(c, req.URL.Path+"/"); rerr == nil {
					return
				}
			}
		}
		e.DefaultHTTPErrorHandler(err, c)
	}
}

// initServer returns the server with its global middlewares and the middlewares
// to set on the routes declared after the static files.
func initServer(cfg *config.WebConfig) (*echo.Echo, []echo.MiddlewareFunc) {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = redirectTrailingSlash(e)
	e.Pre(removeTrailingSlash(e, "/auth/"))

	rate, _ := limiter.NewRateFromFormatted("60-M") // 60 reqs/minute

	lStore := memory.NewStore()
	limitMiddleware := echo.WrapMiddleware(mstdlib.NewMiddleware(limiter.New(lStore, rate)).Handler)

	// Set log config
	if !cfg.Debug {
		e.Use(logger(DefaultWriter))
	} else {
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: DefaultWriter}))
	}

	e.Use(middleware.Recover())

	// Set TrustedProxies
	// Find source IP from proxy
	e.IPExtractor = trustedProxies(cfg.Sec.TrustedProxies)

	// Limit rate request
	e.Use(limitMiddleware)

	// SSL
	useSSL := false
	if cfg.SSL.Crt != "" {
		useSSL = true
	}
	e.Use(MiddlewareSession(useSSL))
	if useSSL {
		e.Use(sslHeaders(cfg.Port))
	}

	// Secure headers
	e.Use(secureHeaders())

	// Load templates
	baseLocalesPath := cfg.Locale.Path

	if _, err := os.Stat(baseLocalesPath); !os.IsNotExist(err) {
		var err error
		I18n, err = i18n.New(i18n.Glob(baseLocalesPath+"/*/*"), cfg.Locale.Langs...)
		if err != nil {
			fmt.Printf("Warning no locale dir: %s\n", err.Error())
		}
	} else {
		I18n, _ = i18n.New(i18n.Glob(""), "en")
	}

	translateLangFunc := func(x string) string { return Tr(cfg.Locale.Lang, x) }

	//	templates in basePath + "/web/templates/**/*.tmpl"
	t := []string{}
	dirs, _ := templateFs.ReadDir("web/templates")
	for k := range dirs {
		files, _ := templateFs.ReadDir("web/templates/" + dirs[k].Name())
		for f := range files {
			t = append(t, fmt.Sprintf("web/templates/%s/%s", dirs[k].Name(), files[f].Name()))
		}
	}
	templ := template.Must(template.New("").Funcs(template.FuncMap{"tr": translateLangFunc}).ParseFS(templateFs, t...))
	e.Renderer = &TemplateRenderer{Templates: templ}
	if cfg.Debug {
		fmt.Printf("\nTemplates loaded:\n\t- %s\n", strings.Join(t, "\n\t- "))
	}

	// Load static files
	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "home/index.tmpl", echo.Map{"appname": cfg.AppName, "appdesc": cfg.AppDesc})
	})

	// Middlewares only set on the routes declared below
	mw := []echo.MiddlewareFunc{
		// Cache static files
		setCacheHeaders(),
		serveStatic("/", EmbedFolder(server, "web/assets")),
		setConfig(cfg),
	}

	css := e.Group("/css", mw...)
	css.Static("", "/assets/css")
	// fonts := e.Group("/fonts", mw...)
	// fonts.Static("", basePath+"/assets/fonts")
	js := e.Group("/js", mw...)
	js.Static("", "/assets/js")

	// serve embedded files for the paths without route
	e.RouteNotFound("/*", echo.NotFoundHandler, mw...)

	return e, mw
}

// routeNotFound declares the not found routes of a group: echo declares them
// with the group middlewares, only the ones of the other routes must be used
// on a path without route.
func routeNotFound(e *echo.Echo, prefix string, m []echo.MiddlewareFunc) {
	e.RouteNotFound(prefix, echo.NotFoundHandler, m...)
	e.RouteNotFound(prefix+"/*", echo.NotFoundHandler, m...)
}

func SetRoutes(cfg *config.WebConfig) *echo.Echo {
	e, m := initServer(cfg)

	mw := middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:_csrf,header:" + echo.HeaderXCSRFToken,
		CookiePath:     "/auth/",
		CookieSecure:   cfg.SSL.Crt != "",
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		ErrorHandler: func(err error, c echo.Context) error {
			return c.String(400, "CSRF token mismatch")
		},
	})

	l := e.Group("/auth", m...)
	l.GET("/login", LoginHandlerForm)
	l.POST("/login", LoginHandler)
	l.GET("/logout", LogoutHandler)

	u := e.Group("/auth/user", m...)
	u.Use(mw)
	u.Use(Auth("self"))
	u.GET("/:id", UserProfile)
	u.POST("/:id", UserChgPasswd)
	u.POST("/otp/:id", UserChgOTP)
	u.POST("/passapp/:id", UserPassApp)

	admin := e.Group("/auth/crud", m...)
	admin.Use(mw)
	admin.Use(Auth("admin"))
	admin.GET("/user/", UserList)
	admin.GET("/user/:id", UserEdit)
	admin.POST("/user/:id", UserUpdate) // for HTML 1.1 form don't have PUT/DELETE methods
	// admin.PUT("/:id", UserUpdate)
	admin.GET("/user/create", UserAdd)
	admin.POST("/user/create", UserCreate)
	admin.POST("/user/del/:id", UserDel) // for HTML 1.1 form don't have PUT/DELETE methods
	// admin.DELETE("/:id", UserDel)

	admin.GET("/reload", CancelChanges)
	admin.GET("/save", SaveChanges)

	admin.GET("/group/", GroupList)
	admin.GET("/group/:id", GroupEdit)
	admin.POST("/group/:id", GroupUpdate)
	admin.GET("/group/create", GroupAdd)
	admin.POST("/group/create", GroupCreate)
	admin.POST("/group/del/:id", GroupDel)

	routeNotFound(e, "/auth", m)
	routeNotFound(e, "/auth/user", m)
	routeNotFound(e, "/auth/crud", m)

	return e
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func setCacheHeaders() echo.MiddlewareFunc {
	data := []byte(time.Now().String())
	etag := fmt.Sprintf("%x", md5.Sum(data)) //nolint:gosec  //only for cache headers
	cacheSince := time.Now().Format(http.TimeFormat)
	cacheUntil := time.Now().AddDate(0, 12, 0).Format(http.TimeFormat)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if strings.Contains(c.Request().URL.Path, "/css/") ||
				strings.Contains(c.Request().URL.Path, "/js/") ||
				strings.Contains(c.Request().URL.Path, "favicon") {
				h := c.Response().Header()
				h.Set("Cache-Control", "public, max-age=604800, immutable")
				h.Set("ETag", etag)
				h.Set("Last-Modified", cacheSince)
				h.Set("Expires", cacheUntil)
			}
			return next(c)
		}
	}
}

func Auth(rolectl string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cfg := c.Get("Cfg").(config.WebConfig)
			GIDcanChgPass := cfg.CfgUsers.GIDcanChgPass
			GIDAdmin := cfg.CfgUsers.GIDAdmin
			GIDuseOtp := cfg.CfgUsers.GIDuseOtp
			username, userid := GetUserID(c)
			if username == "" || userid == "" {
				Log.Info(fmt.Sprintf("%s -- NOK denied old or bad cookie", c.RealIP()))
				return c.Redirect(302, "/auth/logout")
			}
			id := GetUserKey(userid)
			role := "user"
			// search admin role
			groups := Data.Users[id].OtherGroups
			groups = append(groups, Data.Users[id].PrimaryGroup)
			if contains(groups, GIDAdmin) {
				role = "admin"
				Log.Info(fmt.Sprintf("%s -- [%s] is admin", c.RealIP(), username))
			}
			// search allow self change password
			c.Set("Csrf", c.Get(middleware.DefaultCSRFConfig.ContextKey))
			c.Set("CanChgPass", false)
			if contains(groups, GIDcanChgPass) || contains(groups, GIDAdmin) {
				c.Set("CanChgPass", true)
			}
			c.Set("UseOtp", false)
			if contains(groups, GIDuseOtp) {
				c.Set("UseOtp", true)
			}
			c.Set("Login", username)
			c.Set("LoginID", userid)
			c.Set("Role", role)
			c.Set("AppName", cfg.AppName)
			c.Set("MaskOTP", cfg.MaskOTP)
			c.Set("DefaultHomedir", cfg.DefaultHomedir)
			c.Set("DefaultLoginShell", cfg.DefaultLoginShell)
			Log.Info(fmt.Sprintf("%s -- OK [%s] (%s) valid access", c.RealIP(), username, userid))
			return next(c)
		}
	}
}
