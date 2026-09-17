package helpers

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"

	"github.com/gorilla/sessions"

	"github.com/gorilla/securecookie"
)

var blockKey = securecookie.GenerateRandomKey(32)

var CookieSessionName = "appsession"

// sessionCtxKey is the context key used to store the session store.
const sessionCtxKey = "github.com/gorilla/sessions"

// sessionCtx keeps the store and the name of the session used by the request.
type sessionCtx struct {
	name  string
	store sessions.Store
}

func SetSession(c echo.Context, status string) {
	session := defaultSession(c)
	session.Values["status"] = status
	session.Save(c.Request(), c.Response()) //nolint:errcheck // no session
}

// Sessions registers the session store for the request.
func Sessions(name string, store sessions.Store) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(sessionCtxKey, &sessionCtx{name: name, store: store})
			return next(c)
		}
	}
}

func MiddlewareSession(secure bool) echo.MiddlewareFunc {
	// store := sessions.NewCookieStore([]byte(secret))
	store := sessions.NewCookieStore(blockKey)
	store.Options = &sessions.Options{
		//Domain:   "localhost",
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   3600,
		SameSite: http.SameSiteStrictMode,
	}
	return Sessions(CookieSessionName, store)
}

// defaultSession returns the session of the request.
func defaultSession(c echo.Context) *sessions.Session {
	s := c.Get(sessionCtxKey).(*sessionCtx)
	session, _ := s.store.Get(c.Request(), s.name)
	return session
}

func GetUserID(c echo.Context) (userName string, userId string) {
	s := GetSession(c)
	return s.User, s.UserID
}

func GetSession(c echo.Context) Status {
	session := defaultSession(c)
	var s = Status{}
	t := session.Values["status"]
	if t != nil {
		s = StrToStatus(t.(string))
	}
	return s
}

func ClearSession(c echo.Context) {
	cookie := &http.Cookie{
		Name:   CookieSessionName,
		Value:  "",
		Path:   "/auth/",
		MaxAge: -1,
	}

	http.SetCookie(c.Response(), cookie)
}

// Encodage de la valeur du cookie.
func encode(value string) string {
	encode := &url.URL{Path: value}
	return encode.String()
}

// Décodage de la valeur du cookie.
func decode(value string) string {
	decode, _ := url.QueryUnescape(value)
	return decode
}

func SetFlashCookie(c echo.Context, name string, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    encode(value),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   1,
	}

	http.SetCookie(c.Response(), cookie)
}

func GetFlashCookie(c echo.Context, name string) (value string) {
	cookie, err := c.Request().Cookie(name)

	var cookieValue string
	if err == nil {
		cookieValue = cookie.Value
	}

	return decode(cookieValue)
}
