package bmcproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pkilar/lab-manager/internal/model"
)

// idracSessionValue is the -http-session- value the fake iDRAC issues on login.
const idracSessionValue = "SESSIONXYZ"

// fakeIDRAC is an httptest TLS server emulating the iDRAC endpoints the proxy
// touches, plus a counter of /data/logout calls (for the session-cleanup tests).
type fakeIDRAC struct {
	*httptest.Server
	mu      sync.Mutex
	logouts int
}

func (f *fakeIDRAC) logoutCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logouts
}

// newFakeIDRAC returns a fake iDRAC exposing /data/login, /data/logout, a
// cookie-protected resource, a self-referential redirect, a cookie-rotating
// endpoint, and a WebSocket echo.
func newFakeIDRAC(t *testing.T) *fakeIDRAC {
	t.Helper()
	f := &fakeIDRAC{}
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

	mux.HandleFunc("/data/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("-http-session-"); err == nil && c.Value == idracSessionValue {
			f.mu.Lock()
			f.logouts++
			f.mu.Unlock()
		}
		w.WriteHeader(http.StatusSeeOther) // 303, like the real iDRAC
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

	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func hostport(f *fakeIDRAC) string { return strings.TrimPrefix(f.URL, "https://") }

// fakeLookup satisfies ServerLookup for tests.
type fakeLookup map[int64]*model.Server

func (f fakeLookup) GetServer(id int64) (*model.Server, error) {
	s, ok := f[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}
