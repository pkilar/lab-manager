package bmcproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pkilar/lab-manager/internal/model"
)

// idracSessionValue is the -http-session- value the fake iDRAC issues on login.
const idracSessionValue = "SESSIONXYZ"

// newFakeIDRAC returns an httptest TLS server emulating the iDRAC endpoints the
// proxy touches: /data/login, a cookie-protected resource, a self-referential
// redirect, a cookie-rotating endpoint, and a WebSocket echo.
func newFakeIDRAC(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()

	mux.HandleFunc("/data/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("user") != "root" || r.FormValue("password") != "calvin" {
			io.WriteString(w, `<root><status>ok</status><authResult>5</authResult></root>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "-http-session-", Value: idracSessionValue, Path: "/"})
		io.WriteString(w, `<root><status>ok</status><authResult>0</authResult>`+
			`<forwardUrl>index.html?ST1=aaa,ST2=bbb</forwardUrl></root>`)
	})

	requireSession := func(r *http.Request) bool {
		c, err := r.Cookie("-http-session-")
		return err == nil && c.Value == idracSessionValue
	}

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(r) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "unauthorized")
			return
		}
		io.WriteString(w, "secret-content")
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+"/protected", http.StatusFound)
	})

	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "-http-session-", Value: "ROTATED", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "pref", Value: "1", Path: "/", Domain: strings.Split(r.Host, ":")[0]})
		io.WriteString(w, "rotated")
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(r) || r.Header.Get("Origin") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, append([]byte("echo:"), msg...))
		}
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func hostport(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

// fakeLookup satisfies ServerLookup for tests.
type fakeLookup map[int64]*model.Server

func (f fakeLookup) GetServer(id int64) (*model.Server, error) {
	s, ok := f[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}
