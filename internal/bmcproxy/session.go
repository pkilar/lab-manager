package bmcproxy

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// sessionTTL bounds a proxy session's lifetime. After it lapses the user
// re-clicks KVM (the initiator re-runs the handshake).
const sessionTTL = 8 * time.Hour

// proxySession is the server-side state behind one opaque bmcproxy cookie. It
// holds the iDRAC session token to inject upstream — that token is never sent
// to the browser.
type proxySession struct {
	serverID    int64
	idracCookie string // "-http-session-=..." Cookie header value
	expiry      time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*proxySession
	now      func() time.Time // injectable for tests
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]*proxySession{}, now: time.Now}
}

func (s *sessionStore) create(serverID int64, idracCookie string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sessions[id] = &proxySession{serverID: serverID, idracCookie: idracCookie, expiry: s.now().Add(sessionTTL)}
	s.mu.Unlock()
	return id, nil
}

func (s *sessionStore) get(id string) (*proxySession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if s.now().After(sess.expiry) {
		delete(s.sessions, id)
		return nil, false
	}
	return sess, true
}

// updateCookie refreshes the injected iDRAC cookie when the controller rotates
// it mid-session (captured from an upstream Set-Cookie).
func (s *sessionStore) updateCookie(id, idracCookie string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.idracCookie = idracCookie
	}
}

func (s *sessionStore) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.expiry) {
			delete(s.sessions, id)
		}
	}
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
