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
// to the browser. ip is retained so the session can be logged out of the iDRAC
// when it is evicted.
type proxySession struct {
	serverID    int64
	ip          string
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

// create stores a new session and returns it, plus any prior sessions for the
// SAME server (now removed) so the caller can log them out of the iDRAC. This
// caps iDRAC web sessions at ~one per server, so repeated KVM launches don't
// exhaust the iDRAC's small web-session table.
func (s *sessionStore) create(serverID int64, ip, idracCookie string) (id string, displaced []*proxySession, err error) {
	id, err = randomID()
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for oldID, sess := range s.sessions {
		if sess.serverID == serverID {
			displaced = append(displaced, sess)
			delete(s.sessions, oldID)
		}
	}
	s.sessions[id] = &proxySession{serverID: serverID, ip: ip, idracCookie: idracCookie, expiry: s.now().Add(sessionTTL)}
	return id, displaced, nil
}

// get returns a COPY of the session. Returning the *proxySession would let the
// caller read fields after the mutex is released, racing updateCookie, which
// rewrites idracCookie under the lock when the iDRAC rotates it mid-session.
func (s *sessionStore) get(id string) (proxySession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return proxySession{}, false
	}
	if s.now().After(sess.expiry) {
		delete(s.sessions, id)
		return proxySession{}, false
	}
	return *sess, true
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

// gc removes expired sessions and returns them so the caller can log them out
// of the iDRAC.
func (s *sessionStore) gc() []*proxySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var evicted []*proxySession
	for id, sess := range s.sessions {
		if now.After(sess.expiry) {
			evicted = append(evicted, sess)
			delete(s.sessions, id)
		}
	}
	return evicted
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
