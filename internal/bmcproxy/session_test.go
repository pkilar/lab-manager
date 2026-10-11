package bmcproxy

import (
	"testing"
	"time"
)

func TestSessionStoreCreateGetExpire(t *testing.T) {
	s := newSessionStore()
	base := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return base }

	id, _, err := s.create(idracVendor, 42, "10.0.0.1", "-http-session-=ABC")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, ok := s.get(id)
	if !ok || got.serverID != 42 || got.bmcCookie != "-http-session-=ABC" {
		t.Fatalf("get = %+v ok=%v, want serverID 42", got, ok)
	}
	if _, ok := s.get("nope"); ok {
		t.Fatal("unknown id should not resolve")
	}

	s.updateCookie(id, "-http-session-=ROTATED")
	if g, _ := s.get(id); g.bmcCookie != "-http-session-=ROTATED" {
		t.Fatalf("updateCookie not applied: %q", g.bmcCookie)
	}

	// Advance past TTL: get must miss, but the entry stays for gc to log out.
	s.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if _, ok := s.get(id); ok {
		t.Fatal("expired session should not resolve")
	}
}

func TestSessionCreateDisplacesSameServer(t *testing.T) {
	s := newSessionStore()
	id1, disp1, _ := s.create(idracVendor, 1, "10.0.0.1", "-http-session-=A")
	if len(disp1) != 0 {
		t.Fatalf("first create displaced %d", len(disp1))
	}
	id2, disp2, _ := s.create(idracVendor, 2, "10.0.0.2", "-http-session-=B")
	if len(disp2) != 0 {
		t.Fatal("a different server must not be displaced")
	}
	_, disp3, _ := s.create(idracVendor, 1, "10.0.0.1", "-http-session-=C")
	if len(disp3) != 1 || disp3[0].bmcCookie != "-http-session-=A" || disp3[0].ip != "10.0.0.1" {
		t.Fatalf("re-launching server 1 should displace session A, got %+v", disp3)
	}
	if _, ok := s.get(id1); ok {
		t.Fatal("displaced session should be removed")
	}
	if _, ok := s.get(id2); !ok {
		t.Fatal("server-2 session should survive")
	}
}

func TestGCReturnsExpiredForLogout(t *testing.T) {
	s := newSessionStore()
	base := time.Unix(2_000_000, 0)
	s.now = func() time.Time { return base }
	_, _, _ = s.create(idracVendor, 5, "10.0.0.5", "-http-session-=E")
	if got := s.gc(); len(got) != 0 {
		t.Fatalf("nothing should be expired yet, got %d", len(got))
	}
	s.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	got := s.gc()
	if len(got) != 1 || got[0].serverID != 5 || got[0].ip != "10.0.0.5" {
		t.Fatalf("gc should return the expired session, got %+v", got)
	}
	if got2 := s.gc(); len(got2) != 0 {
		t.Fatal("second gc should be empty (already swept)")
	}
}

func TestGetExpiredLeavesSessionForGC(t *testing.T) {
	s := newSessionStore()
	base := time.Unix(3_000_000, 0)
	s.now = func() time.Time { return base }
	id, _, _ := s.create(idracVendor, 7, "10.0.0.7", "-http-session-=X")
	s.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if _, ok := s.get(id); ok {
		t.Fatal("expired session must not resolve")
	}
	got := s.gc()
	if len(got) != 1 || got[0].serverID != 7 || got[0].ip != "10.0.0.7" {
		t.Fatalf("gc must still return the session get() rejected, got %+v", got)
	}
}
