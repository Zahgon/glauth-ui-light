package handlers

import (
	"fmt"

	"github.com/labstack/echo/v4"

	. "glauth-ui-light/config"
	. "glauth-ui-light/helpers"
)

func CancelChanges(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang

	if ok, err := isAdminAccess(c, "CancelChanges", "-"); !ok {
		return err
	}

	if Lock != 0 {
		DataRead, _, err := ReadDB(&cfg)
		if err == nil {
			Data = DataRead
			Lock = 0
			SetFlashCookie(c, "success", Tr(lang, "Changes canceled"))
			Log.Info(fmt.Sprintf("%s -- [%s] changes canceled", c.RealIP(), c.Get("Login").(string)))
		} else {
			SetFlashCookie(c, "warning", err.Error())
		}
	} else {
		SetFlashCookie(c, "warning", Tr(lang, "Nothing to cancel"))
	}

	return c.Redirect(302, "/auth/crud/user")
}

func SaveChanges(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang

	if ok, err := isAdminAccess(c, "SaveChanges", "-"); !ok {
		return err
	}

	if Lock != 0 {
		username := c.Get("Login").(string)
		err := WriteDB(&cfg, Data, username)
		if err == nil {
			Lock = 0
			SetFlashCookie(c, "success", Tr(lang, "Changes saved"))
			Log.Info(fmt.Sprintf("%s -- [%s] changes saved", c.RealIP(), username))
		} else {
			SetFlashCookie(c, "warning", err.Error())
		}
	} else {
		SetFlashCookie(c, "warning", Tr(lang, "Nothing to save"))
	}

	return c.Redirect(302, "/auth/crud/user")
}
