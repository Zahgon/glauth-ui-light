package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	. "glauth-ui-light/config"
	"glauth-ui-light/helpers"
)

var (
	Data    Ctmp
	Lock    int     // number of waiting changes in memory
	Version = "dev" // will be set on build
)

var Log logrus.Logger

func isAdminAccess(c echo.Context, ressource string, id string) (bool, error) {
	login := c.Get("Login").(string)
	loginid := c.Get("LoginID").(string)
	role := c.Get("Role").(string)
	// admin access
	if role != "admin" {
		Log.Info(fmt.Sprintf("-- [%s] (%s) denied admin access to %s : %s", login, loginid, ressource, id))
		return false, c.Redirect(302, "/auth/logout")
	}
	return true, nil
}

func isSelfAccess(c echo.Context, ressource string, id string) (bool, error) {
	login := c.Get("Login").(string)
	loginid := c.Get("LoginID").(string)
	role := c.Get("Role").(string)

	// Self access
	if role != "admin" && loginid != id {
		Log.Info(fmt.Sprintf("-- [%s] (%s) denied self access to %s : %s", login, loginid, ressource, id))
		return false, c.Redirect(302, "/auth/logout")
	}
	return true, nil
}

func render(c echo.Context, data echo.Map, templateName string) error {
	// Set user
	role := c.Get("Role")
	data["userName"], data["userId"] = helpers.GetUserID(c)
	if role != nil && role.(string) == "admin" {
		data["roleAdmin"] = true
	}

	// Set CSRF token in forms
	data["Csrf"] = c.Get("Csrf")

	// Set view elements
	data["lock"] = Lock
	data["version"] = Version
	data["appname"] = c.Get("AppName")
	data["MaskOTP"] = c.Get("MaskOTP")
	data["DefaultHomedir"] = c.Get("DefaultHomedir")
	data["DefaultLoginShell"] = c.Get("DefaultLoginShell")

	canChgPass := c.Get("CanChgPass")
	if canChgPass != nil {
		data["canChgPass"] = canChgPass.(bool)
	}

	useOtp := c.Get("UseOtp")
	if useOtp != nil {
		data["useOtp"] = useOtp.(bool)
	}

	data["groupsinfo"] = GetSpecialGroups(c)

	if data["success"] == nil {
		data["success"] = helpers.GetFlashCookie(c, "success")
	}
	if data["warning"] == nil {
		data["warning"] = helpers.GetFlashCookie(c, "warning")
	}
	if data["error"] == nil {
		data["error"] = helpers.GetFlashCookie(c, "error")
	}

	return c.Render(http.StatusOK, templateName, data)

	/*switch c.Request().Header.Get("Accept") {
	case "application/json":
	          // Respond with JSON
	          c.JSON(http.StatusOK, data["payload"])
	  case "application/xml":
	          // Respond with XML
	          c.XML(http.StatusOK, data["payload"])
	default:
		// Respond with HTML
		c.Render(http.StatusOK, templateName, data)
	}*/
}
