package handlers

import (
	"fmt"

	"github.com/labstack/echo/v4"

	. "glauth-ui-light/config"
	. "glauth-ui-light/helpers"
)

// Self user handlers

func UserProfile(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	if ok, err := isSelfAccess(c, "UserProfile", id); !ok {
		return err
	}

	k, err := ctlUserExist(c, lang, id)
	if k < 0 {
		return err
	}

	u := Data.Users[k]
	userf := UserForm{
		UIDNumber:     u.UIDNumber,
		Mail:          u.Mail,
		Name:          u.Name,
		PrimaryGroup:  u.PrimaryGroup,
		OtherGroups:   u.OtherGroups,
		SN:            u.SN,
		GivenName:     u.GivenName,
		Disabled:      u.Disabled,
		OTPSecret:     u.OTPSecret,
		PassAppBcrypt: u.PassAppBcrypt,
		Lang:          lang,
	}

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	return render(c, echo.Map{"title": u.Name, "u": userf, "currentPage": "profile", "groupdata": Data.Groups}, "user/profile.tmpl")
}

func UserChgPasswd(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	// Ctrl access
	if ok, err := isSelfAccess(c, "UserChgPasswd", id); !ok {
		return err
	}

	k, kerr := ctlUserExist(c, lang, id)
	if k < 0 {
		return kerr
	}

	// Ctrl access with message
	u := Data.Users[k]
	role := c.Get("Role").(string)

	userf := &UserForm{
		UIDNumber:     u.UIDNumber,
		Mail:          u.Mail,
		Name:          u.Name,
		PrimaryGroup:  u.PrimaryGroup,
		OtherGroups:   u.OtherGroups,
		SN:            u.SN,
		GivenName:     u.GivenName,
		Disabled:      u.Disabled,
		OTPSecret:     u.OTPSecret,
		PassAppBcrypt: u.PassAppBcrypt,
		Lang:          lang,
	}
	userf.Errors = make(map[string]string)

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	// application accounts don't change their password
	// users and admins are defined by group set by GIDcanChgPass, GIDAdmin config
	if (role != "admin" && role != "user") || Lock != 0 {
		warning := ""
		if Lock != 0 {
			warning = Tr(lang, "Data locked by admin.")
		}
		return render(c, echo.Map{
			"title":       u.Name,
			"currentPage": "profile",
			"warning":     warning,
			"u":           userf,
			"groupdata":   Data.Groups},
			"user/profile.tmpl")
	}

	pass1 := c.Request().PostFormValue("inputPassword")
	pass2 := c.Request().PostFormValue("inputPassword2")

	// Validate entries
	if pass1 == "" {
		userf.Errors["Password"] = Tr(lang, "Mandatory")
	}
	if pass1 != pass2 {
		userf.Errors["Password2"] = Tr(lang, "Passwords mismatch")
	}
	if pass2 == "" {
		userf.Errors["Password2"] = Tr(lang, "Mandatory")
	}
	if len(userf.Errors) != 0 {
		return render(c, echo.Map{"title": u.Name, "currentPage": "profile", "u": userf, "groupdata": Data.Groups}, "user/profile.tmpl")
	}
	userf.Password = pass1

	// Validate new password
	if !userf.Validate(cfg.PassPolicy) {
		return render(c, echo.Map{"title": u.Name, "currentPage": "profile", "u": userf, "groupdata": Data.Groups}, "user/profile.tmpl")
	}

	(&Data.Users[k]).SetBcryptPass(pass1)
	(&Data.Users[k]).PassSHA256 = "" // no more use of SHA256

	username := c.Get("Login").(string)
	Log.Info(fmt.Sprintf("%s -- %s password changed by %s", c.RealIP(), u.Name, username))

	err := WriteDB(&cfg, Data, username)
	if err != nil {
		return render(c, echo.Map{"title": Tr(lang, "Error"), "currentPage": "profile", "error": err.Error()}, "home/error.tmpl")
	}

	return render(c, echo.Map{
		"title":       u.Name,
		"currentPage": "profile",
		"success":     Tr(lang, "Password updated"),
		"u":           userf,
		"groupdata":   Data.Groups},
		"user/profile.tmpl")
}

func UserChgOTP(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	// Ctrl access
	if ok, err := isSelfAccess(c, "UserChgOTP", id); !ok {
		return err
	}

	k, kerr := ctlUserExist(c, lang, id)
	if k < 0 {
		return kerr
	}

	// Ctrl access with message
	u := Data.Users[k]

	userf := &UserForm{
		UIDNumber:     u.UIDNumber,
		Mail:          u.Mail,
		Name:          u.Name,
		PrimaryGroup:  u.PrimaryGroup,
		OtherGroups:   u.OtherGroups,
		SN:            u.SN,
		GivenName:     u.GivenName,
		Disabled:      u.Disabled,
		OTPSecret:     u.OTPSecret,
		PassAppBcrypt: u.PassAppBcrypt,
		Lang:          lang,
	}
	userf.Errors = make(map[string]string)

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	groups := u.OtherGroups
	groups = append(groups, u.PrimaryGroup)
	useOtp := contains(groups, cfg.CfgUsers.GIDuseOtp)

	if !useOtp || Lock != 0 { // only for members of GIDuseOtp
		warning := ""
		if Lock != 0 {
			warning = Tr(lang, "Data locked by admin.")
		}
		return render(c, echo.Map{
			"title":       u.Name,
			"currentPage": "profile",
			"warning":     warning,
			"navotp":      true,
			"u":           userf,
			"groupdata":   Data.Groups},
			"user/profile.tmpl")
	}

	otp := c.Request().PostFormValue("inputOTPSecret")
	userf.OTPSecret = otp

	// Validate new otpsecret or no change
	if !userf.Validate(cfg.PassPolicy) || otp == (&Data.Users[k]).OTPSecret {
		userf.OTPSecret = (&Data.Users[k]).OTPSecret
		return render(c, echo.Map{"title": u.Name,
			"currentPage": "profile",
			"navotp":      true,
			"u":           userf,
			"groupdata":   Data.Groups}, "user/profile.tmpl")
	}

	(&Data.Users[k]).OTPSecret = userf.OTPSecret

	username := c.Get("Login").(string)
	Log.Info(fmt.Sprintf("%s -- %s otp secret changed by %s", c.RealIP(), u.Name, username))

	err := WriteDB(&cfg, Data, username)
	if err != nil {
		return render(c, echo.Map{"title": Tr(lang, "Error"), "currentPage": "profile", "error": err.Error()}, "home/error.tmpl")
	}

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	return render(c, echo.Map{
		"title":       u.Name,
		"currentPage": "profile",
		"success":     Tr(lang, "OTP updated"),
		"navotp":      true,
		"u":           userf,
		"groupdata":   Data.Groups},
		"user/profile.tmpl")
}

func UserPassApp(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	// Ctrl access
	if ok, err := isSelfAccess(c, "UserPassApp", id); !ok {
		return err
	}

	k, kerr := ctlUserExist(c, lang, id)
	if k < 0 {
		return kerr
	}

	// Ctrl access with message
	u := Data.Users[k]

	userf := &UserForm{
		UIDNumber:     u.UIDNumber,
		Mail:          u.Mail,
		Name:          u.Name,
		PrimaryGroup:  u.PrimaryGroup,
		OtherGroups:   u.OtherGroups,
		SN:            u.SN,
		GivenName:     u.GivenName,
		Disabled:      u.Disabled,
		OTPSecret:     u.OTPSecret,
		PassAppBcrypt: u.PassAppBcrypt,
		Lang:          lang,
	}
	userf.Errors = make(map[string]string)

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	groups := u.OtherGroups
	groups = append(groups, u.PrimaryGroup)
	useOtp := contains(groups, cfg.CfgUsers.GIDuseOtp)

	if !useOtp || Lock != 0 { // only for members of GIDuseOtp
		warning := ""
		if Lock != 0 {
			warning = Tr(lang, "Data locked by admin.")
		}
		return render(c, echo.Map{
			"title":       u.Name,
			"currentPage": "profile",
			"warning":     warning,
			"navotp":      true,
			"u":           userf,
			"groupdata":   Data.Groups},
			"user/profile.tmpl")
	}

	// Read input
	username := c.Get("Login").(string)

	userf.NewPassApp = c.Request().PostFormValue("inputNewPassApp")

	change := false
	// Remove pass app
	for d := 0; d < 3; d++ {
		input := fmt.Sprintf("inputDelPassApp%d", d)
		delpass := c.Request().PostFormValue(input)
		if delpass != "" {
			(&Data.Users[k]).DelPassApp(d)
			change = true
			Log.Info(fmt.Sprintf("%s -- %s passapp removed %d by %s", c.RealIP(), u.Name, d, username))
		}
	}

	// Validate and register newpass
	if userf.NewPassApp != "" {
		if !userf.Validate(cfg.PassPolicy) {
			return render(c, echo.Map{"title": u.Name,
				"currentPage": "profile",
				"navotp":      true,
				"u":           userf,
				"groupdata":   Data.Groups}, "user/profile.tmpl")
		}

		(&Data.Users[k]).AddPassApp(userf.NewPassApp)
		change = true
		Log.Info(fmt.Sprintf("%s -- %s passapp added by %s", c.RealIP(), u.Name, username))
	}

	if change {
		userf.PassAppBcrypt = Data.Users[k].PassAppBcrypt
	}

	err := WriteDB(&cfg, Data, username)
	if err != nil {
		return render(c, echo.Map{"title": Tr(lang, "Error"), "currentPage": "profile", "error": err.Error()}, "home/error.tmpl")
	}

	return render(c, echo.Map{
		"title":       u.Name,
		"currentPage": "profile",
		"success":     Tr(lang, "Tokens changed"),
		"navotp":      true,
		"u":           userf,
		"groupdata":   Data.Groups},
		"user/profile.tmpl")
}
