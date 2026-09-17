package handlers

import (
	"strconv"

	"github.com/labstack/echo/v4"

	"glauth-ui-light/config"
	"glauth-ui-light/helpers"
)

func LoginHandlerForm(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	userName, userId := helpers.GetUserID(c)
	s := helpers.GetSession(c)

	return c.Render(200, "home/login.tmpl", echo.Map{
		"userName":    userName,
		"userId":      userId,
		"currentPage": "login",
		"version":     Version,
		"appname":     cfg.AppName,
		"otp":         s.ReqOTP,
		"warning":     helpers.GetFlashCookie(c, "warning"),
		"error":       helpers.GetFlashCookie(c, "error"),
	})
}

func LoginHandler(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	Log.Debug(c.RealIP(), " - POST /login")
	lang := cfg.Locale.Lang

	s := helpers.GetSession(c)
	s = helpers.FailLimiter(s, 30) // lock 30s after 4 failed logins

	username := c.Request().PostFormValue("username")
	password := c.Request().PostFormValue("password")
	code := c.Request().PostFormValue("code")

	switch {
	case s.Lock: // == true
		s.User = username
		s.UserID = ""
		helpers.SetSession(c, s.ToJSONStr())
		Log.Debug(c.RealIP(), " - Lock Status for ", username)
		helpers.SetFlashCookie(c, "error", helpers.Tr(lang, "Too many errors, come back later"))
		return c.Redirect(302, "/auth/login")
	case username != "" && password != "":
		valid := false
		u, err := GetUserByName(username)
		if err == nil {
			valid = u.ValidPass(password, cfg.PassPolicy.AllowReadSSHA256)
		} else {
			Log.Info(c.RealIP(), " - No user ", username)
		}
		/*if *backend == "test" {
			valid = testValidateUser(username, password)
		}
		if *backend == "ldap" {
			valid = ldapValidateUser(username, password, config)
		}*/
		if valid && !u.Disabled {
			tmpid := strconv.Itoa(u.UIDNumber)
			s.UserID = tmpid
			s.Count = 0

			groups := u.OtherGroups
			groups = append(groups, u.PrimaryGroup)
			useOtp := contains(groups, cfg.CfgUsers.GIDuseOtp)

			// redirect to otp if otp group and secret
			if u.OTPSecret != "" && useOtp {
				s.ReqOTP = true
				s.User = ""
				helpers.SetSession(c, s.ToJSONStr())
				return c.Redirect(302, "/auth/login")
			}
			// Auth success
			s.ReqOTP = false
			s.User = username
			helpers.SetSession(c, s.ToJSONStr())
			return c.Redirect(302, "/auth/user/"+tmpid)
		}
		// Auth failed
		s.User = ""
		s.UserID = ""
		helpers.SetSession(c, s.ToJSONStr())
		if u.Disabled {
			Log.Info(c.RealIP(), " - AUTH failed for ", username, " : Account disabled")
			helpers.SetFlashCookie(c, "warning", helpers.Tr(lang, "Account disabled"))
		} else {
			Log.Info(c.RealIP(), " - AUTH failed for ", username, "Bad credentials")
			helpers.SetFlashCookie(c, "warning", helpers.Tr(lang, "Bad credentials"))
		}
		return c.Redirect(302, "/auth/login")
	case s.UserID != "" && code != "":
		u := Data.Users[GetUserKey(s.UserID)]
		valid := u.ValidOTP(code, !cfg.Tests)
		if !valid {
			return c.Redirect(302, "/auth/login")
		}
		// Auth success
		s.ReqOTP = false
		s.User = u.Name
		helpers.SetSession(c, s.ToJSONStr())
		tmpid := strconv.Itoa(u.UIDNumber)
		return c.Redirect(302, "/auth/user/"+tmpid)
	default:
		Log.Error(c.RealIP(), " - Bad Post params")
		return c.Render(404, "home/login.tmpl", nil)
	}
}

func LogoutHandler(c echo.Context) error {
	cfg := c.Get("Cfg").(config.WebConfig)
	lang := cfg.Locale.Lang

	helpers.ClearSession(c)
	helpers.SetFlashCookie(c, "success", helpers.Tr(lang, "You are disconnected"))
	return c.Redirect(302, "/")
}
