package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// staticHandler serves the embedded read-only asset tree at /static/ (xterm.js
// and friends). Being an embedded FS, it cannot traverse to the host disk.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embed path is a compile-time constant; this never fails
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
