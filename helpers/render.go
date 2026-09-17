package helpers

import (
	"html/template"
	"io"

	"github.com/labstack/echo/v4"
)

/* Html templates rendering */

// TemplateRenderer is the echo.Renderer used to render the html templates.
type TemplateRenderer struct {
	Templates *template.Template
}

// Render renders the named template with the given data.
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.Templates.ExecuteTemplate(w, name, data)
}
