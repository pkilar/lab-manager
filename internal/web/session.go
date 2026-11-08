package web

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/pkilar/lab-manager/internal/model"
)

// Flash is a one-shot UI message (category + text), consumed on the next render.
type Flash struct {
	Category string `json:"c"`
	Message  string `json:"m"`
}

// sessionData is the signed-cookie session: stateless, so it survives restarts
// as long as LAB_MANAGER_SECRET_KEY is stable (the signing key derives from it).
type sessionData struct {
	UID     int64   `json:"uid,omitempty"`
	CSRF    string  `json:"csrf,omitempty"`
	IAT     int64   `json:"iat,omitempty"` // unix seconds at login; bounds the session lifetime
	PV      string  `json:"pv,omitempty"`  // password-version marker; a password change invalidates old sessions
	SID     string  `json:"sid,omitempty"` // random per-login id; logout revokes it server-side
	Flashes []Flash `json:"flashes,omitempty"`
	dirty   bool    // not serialized; set when the session must be re-saved
}

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
)

const (
	sessionCookie = "session"
	// hostSessionCookie is used over HTTPS. The __Host- prefix makes browsers
	// require Secure + Path=/ + no Domain, so a sibling subdomain (the BMC proxy
	// hosts live under the same parent) cannot plant a cookie of this name.
	hostSessionCookie = "__Host-session"
)

// sessionCookieName picks the cookie name matching the request's scheme.
func sessionCookieName(r *http.Request) string {
	if requestScheme(r) == "https" {
		return hostSessionCookie
	}
	return sessionCookie
}

// maxFlashRunes keeps one flash small: the whole session rides in a cookie and
// browsers drop one over ~4 KB, which would silently lose the session.
const maxFlashRunes = 300

// sessionMaxAge is the server-side absolute session lifetime. The cookie itself
// stays a browser-session cookie (no MaxAge/Expires), so closing the browser
// still logs out as before.
const sessionMaxAge = 24 * time.Hour

// passwordVersion derives a marker from the user's password hash, stored in the
// session so a password change invalidates every other session. It is
// domain-separated so it cannot collide with other HMAC uses of the key, and
// reveals nothing useful about the hash.
func (a *App) passwordVersion(passwordHash string) string {
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write([]byte("session-pv\x00" + passwordHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func (a *App) signSession(payload []byte) string {
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) parseSession(cookie string) *sessionData {
	encPayload, encSig, ok := strings.CutLast(cookie, ".")
	if !ok {
		return &sessionData{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return &sessionData{}
	}
	sig, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return &sessionData{}
	}
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return &sessionData{}
	}
	sd := &sessionData{}
	if err := json.Unmarshal(payload, sd); err != nil {
		return &sessionData{}
	}
	return sd
}

func (s *sessionData) flash(category, message string) {
	// Messages can embed text from a BMC; drop control characters and cap the length.
	message = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, message)
	if rs := []rune(message); len(rs) > maxFlashRunes {
		message = string(rs[:maxFlashRunes]) + "…"
	}
	s.Flashes = append(s.Flashes, Flash{Category: category, Message: message})
	s.dirty = true
}

func (s *sessionData) takeFlashes() []Flash {
	f := s.Flashes
	if len(f) > 0 {
		s.Flashes = nil
		s.dirty = true
	}
	return f
}

func (s *sessionData) csrfToken() string {
	if s.CSRF == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		s.CSRF = hex.EncodeToString(b)
		s.dirty = true
	}
	return s.CSRF
}

// login and logout drop the CSRF token so the next csrfToken() mints a fresh
// one: a token planted or observed before authentication must not survive it.
func (s *sessionData) login(uid, iat int64, pv string) {
	s.CSRF = ""
	s.UID = uid
	s.IAT = iat
	s.PV = pv
	s.SID = newSessionID()
	s.dirty = true
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *sessionData) logout() {
	s.CSRF = ""
	s.UID = 0
	s.IAT = 0
	s.PV = ""
	s.SID = ""
	s.dirty = true
}

// sessionWriter flushes the (possibly mutated) session to a Set-Cookie header
// the first time the response is written — cookies must be set before the
// status line, so we hook WriteHeader/Write.
type sessionWriter struct {
	http.ResponseWriter
	app     *App
	sess    *sessionData
	secure  bool // set the Secure cookie flag (request arrived over HTTPS)
	name    string
	legacy  bool // HTTPS request that also carried the plain-HTTP cookie name
	flushed bool
	wrote   bool // a status line or body has been written
}

// Unwrap exposes the underlying writer so http.ResponseController can reach any
// optional interfaces (Flusher, Hijacker, ...) the original writer implements.
func (w *sessionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack lets WebSocket upgrades take over the connection. gorilla/websocket
// type-asserts http.Hijacker on the ResponseWriter directly (it does not go
// through http.ResponseController/Unwrap), so this wrapper must implement it or
// every upgrade through the session middleware fails with 500 (the SOL console).
func (w *sessionWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("sessionWriter: underlying ResponseWriter is not an http.Hijacker")
	}
	return hj.Hijack()
}

func (w *sessionWriter) flushSession() {
	if w.flushed {
		return
	}
	w.flushed = true
	if !w.sess.dirty {
		return
	}
	payload, err := json.Marshal(w.sess)
	if err != nil {
		slog.Error("marshal session", "err", err)
		return
	}
	if w.legacy {
		// Expire the pre-__Host- cookie so it does not linger beside the new one.
		http.SetCookie(w.ResponseWriter, &http.Cookie{
			Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	http.SetCookie(w.ResponseWriter, &http.Cookie{ //nolint:gosec // G124: Secure is set whenever the request is HTTPS
		Name:     w.name,
		Value:    w.app.signSession(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   w.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (w *sessionWriter) WriteHeader(code int) {
	w.wrote = true
	w.flushSession()
	w.ResponseWriter.WriteHeader(code)
}

func (w *sessionWriter) Write(b []byte) (int, error) {
	w.wrote = true
	w.flushSession()
	return w.ResponseWriter.Write(b)
}

// withSession loads the session from the request cookie and makes it available
// via the request context, wrapping the writer so changes persist.
func (a *App) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := &sessionData{}
		name := sessionCookieName(r)
		if c, err := r.Cookie(name); err == nil {
			sess = a.parseSession(c.Value)
		}
		// Set the Secure flag only when the request arrived over HTTPS (directly
		// or via a TLS-terminating proxy like Traefik). The app is also served
		// over plain HTTP on the LAN, where Secure would drop the cookie.
		sw := &sessionWriter{ResponseWriter: w, app: a, sess: sess, secure: requestScheme(r) == "https", name: name}
		if name != sessionCookie {
			_, err := r.Cookie(sessionCookie)
			sw.legacy = err == nil
		}
		// Recover panics from downstream handlers here, where the sessionWriter
		// (which tracks whether a response was written) is in scope. A leaked
		// stack trace is never sent to the client.
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered in handler", "err", rec, "method", r.Method, "path", r.URL.Path)
				if !sw.wrote {
					http.Error(sw, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()
		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

// withCSRF validates a synchronizer token on all unsafe methods, returning 400
// on failure.
func (a *App) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		token := r.PostFormValue("csrf_token")
		if token == "" {
			token = r.Header.Get("X-CSRFToken")
		}
		sess := requestSession(r)
		if sess.CSRF == "" || subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) != 1 {
			http.Error(w, "The CSRF token is missing or invalid.", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireLogin guards a handler. When enforcePasswordGate is true it also
// redirects users who still owe a password change; the login, logout, and
// change-password routes pass false so they stay reachable.
func (a *App) requireLogin(enforcePasswordGate bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := requestSession(r)
		if sess.UID == 0 {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user, err := a.store.GetUserByID(sess.UID)
		if err != nil {
			sess.logout()
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// Cookies without iat or sid predate those features; treat them as expired.
		if sess.IAT == 0 || sess.SID == "" || a.now().After(time.Unix(sess.IAT, 0).Add(sessionMaxAge)) ||
			!hmac.Equal([]byte(sess.PV), []byte(a.passwordVersion(user.PasswordHash))) {
			sess.logout()
			sess.flash("warning", "Your session has expired. Please log in again.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		revoked, err := a.store.SessionRevoked(sess.SID)
		if err != nil {
			// Fail closed: an unreadable revocation list must not admit a revoked session.
			a.serverError(w, r, err)
			return
		}
		if revoked {
			sess.logout()
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if enforcePasswordGate && user.PasswordChangeRequired {
			sess.flash("warning", "You must change your password before continuing.")
			http.Redirect(w, r, "/change-password", http.StatusFound)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxUser, user)))
	}
}

func requestSession(r *http.Request) *sessionData {
	if s, ok := r.Context().Value(ctxSession).(*sessionData); ok {
		return s
	}
	return &sessionData{}
}

func currentUser(r *http.Request) *model.User {
	u, _ := r.Context().Value(ctxUser).(*model.User)
	return u
}
