//nolint
package handlers

/**
 Common functions for handlers tests
**/

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/kataras/i18n"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"

	"github.com/gorilla/sessions"

	. "glauth-ui-light/config"
	. "glauth-ui-light/helpers"
)

// tools

func deleteFile(file string) {
	// delete file
	var err = os.Remove(file)
	if err != nil {
		fmt.Println(err.Error())
		//os.Exit(0)
	}
}

func copyTmpFile(source, dest string) {
	content, _ := ioutil.ReadFile(source)
	ioutil.WriteFile(dest, content, 0640)
}

func resetData() {
	Data.Users = []User{}
	Data.Groups = []Group{}
}

func clean(file string) {
	resetData()
	deleteFile(file + ".1")
	deleteFile(file + ".2")
	copyTmpFile(file+".orig", file)
	deleteFile(file)
}

// testAccessSimple : access without cookie
func testAccessSimple(t *testing.T, router *echo.Echo, method string, url string) (*httptest.ResponseRecorder, string) {
	req, _ := http.NewRequest(method, url, nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code == 302 {
		location, _ := resp.Result().Location()
		fmt.Printf("=> Redirect to: %s\n", location.String())
		url = location.String()
		cookie := resp.Result().Cookies()
		req, _ = http.NewRequest("GET", url, nil)
		if len(cookie) != 0 {
			for _, c := range cookie {
				req.Header.Add("Cookie", c.String())
			}
		}
		resp = httptest.NewRecorder()
		router.ServeHTTP(resp, req)
	}
	return resp, url
}

// testAccess with cookie from login
func testAccess(t *testing.T, router *echo.Echo, method string, testurl string) (*httptest.ResponseRecorder, string) {
	req, _ := http.NewRequest(method, testurl, nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code == 302 {
		location, _ := resp.Result().Location()
		fmt.Printf("=> Redirect to: %s\n", location.String())
		testurl = location.String()
		req, _ = http.NewRequest("GET", testurl, nil)
		resp = httptest.NewRecorder()
		router.ServeHTTP(resp, req)
	}
	return resp, testurl
}

// testLogin
func testLogin(t *testing.T, r *echo.Echo, login string, pass string, s []*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	form := url.Values{}
	form.Add("username", login)
	form.Add("password", pass)
	req, err := http.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	if len(s) != 0 {
		for _, c := range s {
			req.Header.Add("Cookie", c.String())
		}
	}
	req.PostForm = form
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-Urlencoded")
	if err != nil {
		fmt.Println(err)
	}
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	// fmt.Printf("%+v\n",resp)
	if login == "" || pass == "" {
		return resp, nil
	}
	assert.Equal(t, 302, resp.Code, "http POST success redirect to Edit")
	newurl, _ := resp.Result().Location()
	fmt.Printf("=> Redirect to: %s\n", newurl.String())
	req, _ = http.NewRequest("GET", newurl.String(), nil)
	cookie := resp.Result().Cookies()
	if len(cookie) != 0 {
		for _, c := range cookie {
			req.Header.Add("Cookie", c.String())
		}
	}
	fmt.Printf("=> Cookie: %+v\n", cookie[0])
	//fmt.Printf("=> req: %+v\n", req)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp, cookie
}

// testLogin with otp
func testCode(t *testing.T, router *echo.Echo, code string, session []*http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Add("code", code)
	req, err := http.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	if len(session) != 0 {
		for _, c := range session {
			req.Header.Add("Cookie", c.String())
		}
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-Urlencoded")
	if err != nil {
		fmt.Println(err)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	// fmt.Printf("%+v\n",resp)
	if code == "" {
		return resp
	}
	assert.Equal(t, 302, resp.Code, "http POST success redirect to Edit")
	newurl, _ := resp.Result().Location()
	fmt.Printf("=> Redirect to: %s\n", newurl.String())
	cookie := resp.Result().Cookies()
	fmt.Printf("=> Cookie: %+v\n", cookie)
	return resp
}

// mock routes function

func setConfigTest(cfg WebConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("Cfg", cfg)
			// set values when auth is bypassed
			c.Set("AppName", cfg.AppName)
			c.Set("MaskOTP", cfg.MaskOTP)
			c.Set("DefaultHomedir", cfg.DefaultHomedir)
			c.Set("DefaultLoginShell", cfg.DefaultLoginShell)
			return next(c)
		}
	}
}

func SetUserTest(login string, loginID string, role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("Login", login)
			c.Set("LoginID", loginID)
			c.Set("Role", role)
			return next(c)
		}
	}
}

func InitRouterTest(cfg WebConfig) *echo.Echo {
	r := echo.New()
	r.HideBanner = true
	r.HidePort = true
	r.Use(middleware.Logger())
	r.Use(middleware.Recover())
	basePath := cfg.Locale.Path

	r.Static("/css", basePath+"/web/assets/css")
	r.Static("/fonts", basePath+"/web/assets/fonts")
	r.Static("/js", basePath+"/web/assets/js")

	var err error
	I18n, err = i18n.New(i18n.Glob(basePath+"/*/*"), cfg.Locale.Langs...)
	if err != nil {
		panic(err)
	}

	translateLangFunc := func(x string) string { return Tr(cfg.Locale.Lang, x) }

	templ := template.Must(template.New("").Funcs(template.FuncMap{"tr": translateLangFunc}).ParseGlob("../routes/web/templates/**/*.tmpl"))
	r.Renderer = &TemplateRenderer{Templates: templ}

	store := sessions.NewCookieStore([]byte("somesecret"))
	store.Options = &sessions.Options{
		//Domain:   "localhost",
		SameSite: http.SameSiteStrictMode,
	}
	r.Use(Sessions("session", store))

	r.Use(setConfigTest(cfg))
	return r

}

// some default test values

func initUsersValues() {
	v1 := User{
		Name:         "user1",
		UIDNumber:    5000,
		PrimaryGroup: 6501,
		PassSHA256:   "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a",
		OTPSecret:    "3hnvnk4ycv44glzigd6s25j4dougs3rk",
	}
	Data.Users = append(Data.Users, v1)
	v2 := User{
		Name:         "user2",
		UIDNumber:    5001,
		PrimaryGroup: 6504,
		OtherGroups:  []int{6501, 6503},
	}
	Data.Users = append(Data.Users, v2)
	v3 := User{
		Name:         "serviceapp",
		UIDNumber:    5002,
		PrimaryGroup: 6502,
		PassSHA256:   "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a",
	}
	Data.Users = append(Data.Users, v3)
	g1 := Group{
		Name:      "group1",
		GIDNumber: 6502,
	}
	Data.Groups = append(Data.Groups, g1)
	g2 := Group{
		Name:      "group2",
		GIDNumber: 6503,
	}
	Data.Groups = append(Data.Groups, g2)
}
