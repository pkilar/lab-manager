package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/pkilar/lab-manager/internal/console"
)

//go:embed templates
var templateFS embed.FS

// Templates holds the parsed template sets: content pages (each composed with
// base.html) and the standalone console launch pages.
type Templates struct {
	pages   map[string]*template.Template
	console map[string]*template.Template
}

var templateFuncs = template.FuncMap{
	// js renders a value as a JSON literal for safe embedding in <script>
	// blocks.
	"js": func(v any) template.JS {
		b, err := json.Marshal(v)
		if err != nil {
			return template.JS("null")
		}
		return template.JS(b)
	},
}

func parseTemplates() (*Templates, error) {
	t := &Templates{
		pages:   map[string]*template.Template{},
		console: map[string]*template.Template{},
	}
	for _, name := range []string{"index", "new_server", "edit_server", "login", "change_password"} {
		tmpl, err := template.New("base.html").Funcs(templateFuncs).ParseFS(templateFS,
			"templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse page %s: %w", name, err)
		}
		t.pages[name] = tmpl
	}
	for _, name := range []string{"console_launch", "console_launch_idrac", "console_launch_supermicro", "console_sol"} {
		tmpl, err := template.New(name+".html").Funcs(templateFuncs).ParseFS(templateFS, "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse console %s: %w", name, err)
		}
		t.console[name] = tmpl
	}
	return t, nil
}

func (a *App) renderPage(w http.ResponseWriter, name string, status int, data any) {
	tmpl, ok := a.tmpl.pages[name]
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		log.Printf("ERROR: render page %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (a *App) renderConsole(w http.ResponseWriter, name string, data any) {
	tmpl, ok := a.tmpl.console[name]
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name+".html", data); err != nil {
		log.Printf("ERROR: render console %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// baseData carries the fields every content page needs from the layout: flash
// messages, the WoL feature flag, and the CSRF token.
type baseData struct {
	Flashes    []Flash
	WolEnabled bool
	CSRF       string
}

func (a *App) baseData(r *http.Request) baseData {
	sess := requestSession(r)
	return baseData{
		Flashes:    sess.takeFlashes(),
		WolEnabled: a.wolEnabled,
		CSRF:       sess.csrfToken(),
	}
}

// simplePage is the view-model for pages that need nothing beyond baseData.
type simplePage struct {
	baseData
}

// ---- index ---------------------------------------------------------------

type indexData struct {
	baseData
	Servers []serverRow
}

type serverRow struct {
	ID               int64
	Name             string
	NotesPreview     string
	NotesTruncated   bool
	IPAddress        string
	BMCType          string
	HasCreds         bool
	HasMAC           bool
	Status           string
	StatusOn         bool
	HasLastUpdated   bool
	LastUpdatedUTC   string // naive-UTC ISO form for the data-utc attribute
	LastUpdatedLocal string // server-side fallback, overridden client-side by JS
}

// ---- edit ----------------------------------------------------------------

type editData struct {
	baseData
	Server editServerRow
}

type editServerRow struct {
	ID             int64
	Name           string
	IPAddress      string
	BMCType        string
	RedfishUser    string
	IPMIUser       string
	MACAddress     string
	Notes          string
	HasRedfishUser bool
	HasIPMIUser    bool
}

// ---- console pages -------------------------------------------------------

type consoleGenericData struct {
	ServerName  string
	BMCType     string
	ConsoleURL  string
	Username    string
	Password    string
	HasUsername bool
}

type consoleSupermicroData struct {
	ServerName  string
	IPAddress   string
	LoginURL    string
	ConsoleURL  string
	Username    string
	Password    string
	HasUsername bool
}

type consoleIdracData struct {
	ServerID    int64
	ServerName  string
	IPAddress   string
	ConsoleURL  string
	Username    string
	Password    string
	HasUsername bool
	Auth        console.IDRACAuthResult
}

type consoleSOLData struct {
	ServerID   int64
	ServerName string
}
