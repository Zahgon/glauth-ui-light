package handlers

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"encoding/base32"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp"

	passwordvalidator "github.com/wagslane/go-password-validator"

	. "glauth-ui-light/config"
	. "glauth-ui-light/helpers"
)

// defaultMultipartMemory is the memory limit used to parse multipart forms.
const defaultMultipartMemory = 32 << 20 // 32 MB

// Validate entries

var rxEmail = regexp.MustCompile(".+@.+\\..+") //nolint
var rxName = regexp.MustCompile("^[a-z0-9]+$")

var rxBadChar = regexp.MustCompile("[<>&*%$'«».,;:!` ]+")

type UserForm struct {
	UIDNumber     int
	Name          string
	Mail          string
	Homedir       string
	LoginShell    string
	SN            string
	GivenName     string
	Password      string
	OTPSecret     string
	OTPImg        string
	PassAppBcrypt []string
	SSHKeys       []string
	NewPassApp    string
	PrimaryGroup  int
	OtherGroups   []int
	Disabled      bool
	Errors        map[string]string
	Lang          string
}

func (userf *UserForm) CreateOTPimg(appname string) {
	url := fmt.Sprintf("otpauth://totp/%s%%3A%s?secret=%s&issuer=%s", appname, userf.Name, userf.OTPSecret, appname)
	if appname == "" {
		fmt.Println("totp.Generate: Mandatory AppName")
		return
	}
	key, _ := otp.NewKeyFromURL(url)
	var buf bytes.Buffer
	img, _ := key.Image(200, 200)
	e := png.Encode(&buf, img)
	if e != nil {
		fmt.Println("png.Encode: " + e.Error())
		return
	}
	userf.OTPImg = base64.StdEncoding.EncodeToString(buf.Bytes())
}

func (userf *UserForm) Validate(cfg PassPolicy) bool {
	lang := userf.Lang
	userf.Errors = make(map[string]string)

	match := rxEmail.MatchString(userf.Mail)
	if userf.Mail != "" && !match {
		userf.Errors["Mail"] = Tr(lang, "Please enter a valid email address")
	}

	p := userf.Password
	if p != "" {
		switch {
		case len(p) < cfg.Min:
			userf.Errors["Password"] = Tr(lang, "Too short")
		case len(p) > cfg.Max:
			userf.Errors["Password"] = Tr(lang, "Too long")
		case cfg.Entropy != 0:
			err := passwordvalidator.Validate(p, float64(cfg.Entropy))
			if err != nil {
				userf.Errors["Password"] = Tr(lang, "Insecure password")
			}
		}
	}

	np := userf.NewPassApp
	if np != "" {
		switch {
		case len(np) < cfg.Min:
			userf.Errors["NewPassApp"] = Tr(lang, "Too short")
		case len(np) > cfg.Max:
			userf.Errors["NewPassApp"] = Tr(lang, "Too long")
		}
	}

	o := userf.OTPSecret
	if o != "" {
		_, err := base32.StdEncoding.DecodeString(strings.ToUpper(o))
		switch {
		case len(o) < 16:
			userf.Errors["OTPSecret"] = Tr(lang, "Too short")
		case len(o) > 33:
			userf.Errors["OTPSecret"] = Tr(lang, "Too long")
		case err != nil:
			userf.Errors["OTPSecret"] = Tr(lang, "Wrong base32")
		}
	}

	n := userf.Name
	matchName := rxName.MatchString(n)
	switch {
	case strings.TrimSpace(n) == "":
		userf.Errors["Name"] = Tr(lang, "Mandatory")
	case len(n) < 2:
		userf.Errors["Name"] = Tr(lang, "Too short")
	case len(n) > 16:
		userf.Errors["Name"] = Tr(lang, "Too long")
	case !matchName:
		userf.Errors["Name"] = Tr(lang, "Bad character")
	}
	for k := range Data.Users {
		if Data.Users[k].Name == n && Data.Users[k].UIDNumber != userf.UIDNumber {
			userf.Errors["Name"] = Tr(lang, "Name already used")
			break
		}
	}

	matchBadSN := rxBadChar.MatchString(userf.SN)
	if userf.SN != "" && len(userf.SN) > 32 {
		userf.Errors["SN"] = Tr(lang, "Too long")
	}
	if userf.SN != "" && matchBadSN {
		userf.Errors["SN"] = Tr(lang, "Bad character")
	}

	matchBadGname := rxBadChar.MatchString(userf.GivenName)
	if userf.GivenName != "" && len(userf.GivenName) > 32 {
		userf.Errors["GivenName"] = Tr(lang, "Too long")
	}
	if userf.GivenName != "" && matchBadGname {
		userf.Errors["GivenName"] = Tr(lang, "Bad character")
	}

	if userf.UIDNumber < 0 {
		userf.Errors["UIDNumber"] = Tr(lang, "Unknown user")
	}

	matchBadHomedir := rxBadChar.MatchString(userf.Homedir)
	if userf.Homedir != "" && len(userf.Homedir) > 128 {
		userf.Errors["Homedir"] = Tr(lang, "Too long")
	}
	if userf.Homedir != "" && matchBadHomedir {
		userf.Errors["Homedir"] = Tr(lang, "Bad character")
	}

	validLoginShell := []string{"/bin/bash", "/bin/sh", "/bin/false"}
	if userf.LoginShell != "" && strContains(validLoginShell, userf.LoginShell) == false {
		userf.Errors["LoginShell"] = Tr(lang, "Forbidden LoginShell")
	}

	return len(userf.Errors) == 0
}

func strContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Helpers

func ctlUserExist(c echo.Context, lang string, id string) (int, error) {
	k := GetUserKey(id)
	if k < 0 {
		return -1, render(c, echo.Map{"title": Tr(lang, "Error"), "currentPage": "user", "error": Tr(lang, "Unknown user")}, "home/error.tmpl")
	}
	return k, nil
}

func GetUserKey(id string) int {
	i := -1
	intId, _ := strconv.Atoi(id)
	for k := range Data.Users {
		if Data.Users[k].UIDNumber == intId {
			i = k
			break
		}
	}
	return i
}

func GetUserByName(name string) (User, error) {
	for k := range Data.Users {
		if Data.Users[k].Name == name {
			return Data.Users[k], nil
		}
	}
	return User{}, fmt.Errorf("unknown user")
}

// Handlers

func UserList(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang

	if ok, err := isAdminAccess(c, "UserList", "-"); !ok {
		return err
	}

	hg := make(map[int]string)
	for k := range Data.Groups {
		hg[Data.Groups[k].GIDNumber] = Data.Groups[k].Name
	}
	return render(c, echo.Map{"title": Tr(lang, "Users page"), "currentPage": "user", "userdata": Data.Users, "hashgroups": hg}, "user/list.tmpl")
}

func UserEdit(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	if ok, err := isAdminAccess(c, "UserEdit", id); !ok {
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
		Homedir:       u.Homedir,
		LoginShell:    u.LoginShell,
		PrimaryGroup:  u.PrimaryGroup,
		OtherGroups:   u.OtherGroups,
		SN:            u.SN,
		GivenName:     u.GivenName,
		Disabled:      u.Disabled,
		OTPSecret:     u.OTPSecret,
		PassAppBcrypt: u.PassAppBcrypt,
		SSHKeys:       u.SSHKeys,
		Lang:          lang,
	}

	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	return render(c, echo.Map{"title": Tr(lang, "Edit user"), "currentPage": "user", "u": userf, "groupdata": Data.Groups}, "user/edit.tmpl")
}

func UserUpdate(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	if ok, err := isAdminAccess(c, "UserUpdate", id); !ok {
		return err
	}

	k, kerr := ctlUserExist(c, lang, id)
	if k < 0 {
		return kerr
	}

	// Convert string to right format
	var err error
	var pg int

	if c.Request().PostFormValue("inputGroup") != "" {
		pg, err = strconv.Atoi(c.Request().PostFormValue("inputGroup"))
	}
	_ = c.Request().ParseMultipartForm(defaultMultipartMemory)
	ogStr := c.Request().PostForm["inputOtherGroup"]
	d := false
	if c.Request().PostFormValue("inputDisabled") == "on" {
		d = true
	}
	og := []int{}
	for k := range ogStr {
		i, e := strconv.Atoi(ogStr[k])
		if e != nil {
			err = e
		}
		og = append(og, i)
	}
	if err != nil {
		return render(c, echo.Map{"title": Tr(lang, "Error"), "currentPage": "user", "error": err.Error()}, "home/error.tmpl")
	}

	// Bind form to struct
	userf := &UserForm{
		UIDNumber:     Data.Users[k].UIDNumber,
		Mail:          c.Request().PostFormValue("inputMail"),
		Name:          c.Request().PostFormValue("inputName"),
		Homedir:       c.Request().PostFormValue("inputHomedir"),
		LoginShell:    c.Request().PostFormValue("inputLoginShell"),
		SN:            c.Request().PostFormValue("inputSN"),
		GivenName:     c.Request().PostFormValue("inputGivenName"),
		Password:      c.Request().PostFormValue("inputPassword"),
		OTPSecret:     c.Request().PostFormValue("inputOTPSecret"),
		NewPassApp:    c.Request().PostFormValue("inputNewPassApp"),
		PassAppBcrypt: Data.Users[k].PassAppBcrypt,
		PrimaryGroup:  pg,
		OtherGroups:   og,
		Disabled:      d,
		Lang:          lang,
	}
	// fmt.Printf("%+v\n", userf)
	if userf.OTPSecret != "" {
		userf.CreateOTPimg(cfg.AppName)
	}

	// Validate entries
	if !userf.Validate(cfg.PassPolicy) {
		return render(c, echo.Map{"title": Tr(lang, "Edit user"), "currentPage": "user", "u": userf, "groupdata": Data.Groups}, "user/edit.tmpl")
	}

	// Update Data
	// updateUser := &Data.Users[k]
	(&Data.Users[k]).Name = userf.Name
	(&Data.Users[k]).Homedir = userf.Homedir
	(&Data.Users[k]).LoginShell = userf.LoginShell
	(&Data.Users[k]).PrimaryGroup = userf.PrimaryGroup
	(&Data.Users[k]).OtherGroups = og
	(&Data.Users[k]).SN = userf.SN
	(&Data.Users[k]).GivenName = userf.GivenName
	(&Data.Users[k]).Mail = userf.Mail
	(&Data.Users[k]).Disabled = d
	(&Data.Users[k]).OTPSecret = userf.OTPSecret
	if userf.Password != "" { // optional set password
		(&Data.Users[k]).PassSHA256 = "" // no more use of SHA256
		(&Data.Users[k]).SetBcryptPass(userf.Password)
	}

	for d := 0; d < 3; d++ {
		input := fmt.Sprintf("inputDelPassApp%d", d)
		delpass := c.Request().PostFormValue(input)
		if delpass != "" {
			(&Data.Users[k]).DelPassApp(d)
		}
	}
	if userf.NewPassApp != "" {
		(&Data.Users[k]).AddPassApp(userf.NewPassApp)
	}
	userf.PassAppBcrypt = Data.Users[k].PassAppBcrypt

	Lock++

	Log.Info(fmt.Sprintf("%s -- %s updated by %s", c.RealIP(), userf.Name, c.Get("Login").(string)))

	return render(c, echo.Map{
		"title":       Tr(lang, "Edit user"),
		"currentPage": "user",
		"success":     "«" + userf.Name + "» updated",
		"u":           userf,
		"groupdata":   Data.Groups},
		"user/edit.tmpl")
}

func UserAdd(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang

	if ok, err := isAdminAccess(c, "UserAdd", "-"); !ok {
		return err
	}

	return render(c, echo.Map{"title": Tr(lang, "Add user"), "currentPage": "user"}, "user/create.tmpl")
}

func UserCreate(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang

	if ok, err := isAdminAccess(c, "UserCreate", "-"); !ok {
		return err
	}

	// Bind form to struct
	userf := &UserForm{
		Name: c.Request().PostFormValue("inputName"),
		Lang: lang,
	}
	// Validate entries
	if !userf.Validate(cfg.PassPolicy) {
		return render(c, echo.Map{"title": Tr(lang, "Add user"), "currentPage": "user", "u": userf, "groupdata": Data.Groups}, "user/create.tmpl")
	}

	// Create new id
	nextID := cfg.CfgUsers.Start - 1 // start uidnumber via config
	for k := range Data.Users {
		if Data.Users[k].UIDNumber >= nextID {
			nextID = Data.Users[k].UIDNumber
		}
	}
	userf.UIDNumber = nextID + 1
	// Add User to Data
	newUser := User{UIDNumber: userf.UIDNumber, Name: userf.Name}
	Data.Users = append(Data.Users, newUser)

	Lock++

	Log.Info(fmt.Sprintf("%s -- %s created by %s", c.RealIP(), newUser.Name, c.Get("Login").(string)))

	SetFlashCookie(c, "success", "«"+newUser.Name+"» added")
	return c.Redirect(302, fmt.Sprintf("/auth/crud/user/%d", newUser.UIDNumber))
}

func UserDel(c echo.Context) error {
	cfg := c.Get("Cfg").(WebConfig)
	lang := cfg.Locale.Lang
	id := c.Param("id")

	if ok, err := isAdminAccess(c, "UserDel", id); !ok {
		return err
	}

	k, err := ctlUserExist(c, lang, id)
	if k < 0 {
		return err
	}

	deletedUser := Data.Users[k]

	Data.Users = append(Data.Users[:k], Data.Users[k+1:]...)

	Lock++

	Log.Info(fmt.Sprintf("%s -- %s deleted by %s", c.RealIP(), deletedUser.Name, c.Get("Login").(string)))

	SetFlashCookie(c, "success", "«"+deletedUser.Name+"» deleted")
	return c.Redirect(302, "/auth/crud/user")
}
