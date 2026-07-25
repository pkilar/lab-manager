package bmcproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		// The real iDRAC's login CGI is order-sensitive: a body putting password
		// before user is refused with authResult 1 even when the credentials are
		// correct (verified on iDRAC8 firmware ~2.6x). r.FormValue is
		// order-insensitive, so parsing that way made this fixture MORE forgiving
		// than the hardware and hid a bug that broke every server-side login.
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if !strings.HasPrefix(string(raw), "user=") {
			io.WriteString(w, `<root><status>ok</status><authResult>1</authResult>`+
				`<forwardUrl>index.html</forwardUrl></root>`)
			return
		}
		form, _ := url.ParseQuery(string(raw))
		if form.Get("user") != "root" || form.Get("password") != "calvin" {
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

	// /echo reports the raw query string as received plus the client-controlled
	// forwarding headers, so tests can assert what does and does not reach the BMC.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "rawquery=%s|xff=%s|xfh=%s|xfp=%s|fwd=%s|xrip=%s",
			r.URL.RawQuery,
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("Forwarded"),
			r.Header.Get("X-Real-Ip"))
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
	t.Cleanup(f.Close)
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
