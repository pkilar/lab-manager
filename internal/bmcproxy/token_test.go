package bmcproxy

import "testing"

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	tok := mintToken(secret, 7)
	if !verifyToken(secret, tok, 7) {
		t.Fatal("valid token rejected")
	}
	if verifyToken(secret, tok, 8) {
		t.Fatal("token accepted for wrong server id")
	}
	if verifyToken([]byte("other"), tok, 7) {
		t.Fatal("token accepted under wrong secret")
	}
	if verifyToken(secret, "garbage", 7) {
		t.Fatal("garbage token accepted")
	}
}
