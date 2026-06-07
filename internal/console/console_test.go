package console

import "testing"

func TestConsoleTokenRoundTrip(t *testing.T) {
	m := NewManager([]byte("test-secret-key"))
	tok := m.GenerateToken(7, 3)
	if !m.VerifyToken(tok, 7, 3) {
		t.Fatal("valid token rejected")
	}
	if m.VerifyToken(tok, 8, 3) {
		t.Fatal("token accepted for wrong server")
	}
	if m.VerifyToken(tok, 7, 4) {
		t.Fatal("token accepted for wrong user")
	}
	if m.VerifyToken("garbage", 7, 3) {
		t.Fatal("garbage token accepted")
	}
}
