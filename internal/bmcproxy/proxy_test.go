package bmcproxy

import "testing"

func newTestManager() *Manager {
	return NewManager(fakeLookup{}, []byte("secret"), "pi.home.kilar.net")
}

func TestHostServerID(t *testing.T) {
	m := newTestManager()
	cases := []struct {
		host   string
		wantID int64
		wantOK bool
	}{
		{"idrac-1.pi.home.kilar.net", 1, true},
		{"idrac-42.pi.home.kilar.net:443", 42, true},
		{"lab.pi.home.kilar.net", 0, false},
		{"idrac-1.evil.com", 0, false},
		{"idrac-x.pi.home.kilar.net", 0, false},
		{"pi.home.kilar.net", 0, false},
	}
	for _, c := range cases {
		id, ok := m.HostServerID(c.host)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("HostServerID(%q) = (%d,%v), want (%d,%v)", c.host, id, ok, c.wantID, c.wantOK)
		}
	}
}

func TestEnabledAndURLs(t *testing.T) {
	if NewManager(fakeLookup{}, nil, "").Enabled() {
		t.Fatal("empty domain should be disabled")
	}
	m := newTestManager()
	if !m.Enabled() {
		t.Fatal("configured domain should be enabled")
	}
	tok := m.MintToken(3)
	if got := m.AuthURL(3, tok); got != "https://idrac-3.pi.home.kilar.net/__labmgr/auth?token="+tok {
		t.Fatalf("AuthURL = %q", got)
	}
	if got := m.appBaseURL(); got != "https://lab.pi.home.kilar.net" {
		t.Fatalf("appBaseURL = %q", got)
	}
}
