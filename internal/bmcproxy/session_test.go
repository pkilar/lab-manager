package bmcproxy

import (
	"testing"
	"time"
)

func TestSessionStoreCreateGetExpire(t *testing.T) {
	s := newSessionStore()
	base := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return base }

	id, err := s.create(42, "-http-session-=ABC")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, ok := s.get(id)
	if !ok || got.serverID != 42 || got.idracCookie != "-http-session-=ABC" {
		t.Fatalf("get = %+v ok=%v, want serverID 42", got, ok)
	}
	if _, ok := s.get("nope"); ok {
		t.Fatal("unknown id should not resolve")
	}

	s.updateCookie(id, "-http-session-=ROTATED")
	if g, _ := s.get(id); g.idracCookie != "-http-session-=ROTATED" {
		t.Fatalf("updateCookie not applied: %q", g.idracCookie)
	}

	// Advance past TTL: get must miss and the entry must be swept.
	s.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if _, ok := s.get(id); ok {
		t.Fatal("expired session should not resolve")
	}
}
