package helpers

import (
	"fmt"
	"strconv"

	"github.com/labstack/echo/v4"

	"glauth-ui-light/config"
)

func GetUserByName(name string) (config.User, error) {
	for k := range Data.Users {
		if Data.Users[k].Name == name {
			return Data.Users[k], nil
		}
	}
	return config.User{}, fmt.Errorf("unknown user")
}

func LoginTestHandlerForm(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	userName, userId := GetUserID(c)

	return c.Render(200, "home/login.tmpl", echo.Map{
		"userName":    userName,
		"userId":      userId,
		"currentPage": "login",
		"appname":     cfg.AppName,
		"warning":     GetFlashCookie(c, "warning"),
		"error":       GetFlashCookie(c, "error"),
	})
}

func LoginTestHandler(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	fmt.Println(" - POST /login")
	lang := cfg.Locale.Lang

	s := GetSession(c)
	s = FailLimiter(s, 30) // lock 30s after 4 failed logins

	username := c.Request().PostFormValue("username")
	password := c.Request().PostFormValue("password")

	switch {
	case s.Lock: // == true
		s.User = username
		s.UserID = ""
		SetSession(c, s.ToJSONStr())
		fmt.Println(" - Lock Status for ", username)
		SetFlashCookie(c, "error", Tr(lang, "Too many errors, come back later"))
		return c.Redirect(302, "/auth/login")
	case username != "" && password != "":
		valid := false
		u, err := GetUserByName(username)
		if err == nil {
			valid = u.ValidPass(password, cfg.PassPolicy.AllowReadSSHA256)
		} else {
			fmt.Println(" - No user ", username)
		}
		/*if *backend == "test" {
			valid = testValidateUser(username, password)
		}
		if *backend == "ldap" {
			valid = ldapValidateUser(username, password, config)
		}*/
		if valid {
			tmpid := strconv.Itoa(u.UIDNumber)
			s.User = username
			s.UserID = tmpid
			s.Count = 0

			SetSession(c, s.ToJSONStr())
			return c.Redirect(302, "/user/"+tmpid)
		} else {
			fmt.Println(" - AUTHENTICATION failed for ", username)
			s.User = username
			s.UserID = ""
			SetSession(c, s.ToJSONStr())
			SetFlashCookie(c, "warning", Tr(lang, "Bad credentials"))
			return c.Redirect(302, "/auth/login")
		}
	default:
		fmt.Println(" - Bad Post params")
		return c.Render(404, "home/login.tmpl", nil)
	}
}

func LogoutTestHandler(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	lang := cfg.Locale.Lang

	ClearSession(c)
	SetFlashCookie(c, "success", Tr(lang, "You are disconnected"))
	return c.Redirect(302, "/")
}
