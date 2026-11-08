package console

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

func TestTokenIsPurposeBound(t *testing.T) {
	secret := []byte("k")
	m := NewManager(secret)
	tok := m.GenerateToken(3, 4)
	for range 2 {
		if !m.VerifyToken(tok, 3, 4) {
			t.Fatal("valid token must verify, repeatedly (launch page reloads)")
		}
	}
	// A signature over the bare message, as any other user of the key could
	// produce, must not verify.
	ts := m.now().Unix()
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%d:%d:%d", 3, 4, ts)
	bare := base64.URLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s", ts, hex.EncodeToString(h.Sum(nil))))
	if m.VerifyToken(bare, 3, 4) {
		t.Fatal("token without the purpose prefix accepted")
	}
}

func TestLoginConfigIPv6AndInvalidAddress(t *testing.T) {
	useRealBMCHost(t)
	cfg := LoginConfigFor(&model.Server{IPAddress: "2001:db8::1", BMCType: model.BMCIDRAC, RedfishUser: "root"})
	if cfg == nil || !strings.HasPrefix(cfg.ConsoleURL, "https://[2001:db8::1]/") {
		t.Fatalf("cfg = %+v", cfg)
	}
	if LoginConfigFor(&model.Server{IPAddress: "evil.example/x", BMCType: model.BMCIDRAC, RedfishUser: "root"}) != nil {
		t.Fatal("non-IP address produced a config")
	}
	res := NewManager([]byte("k")).PreAuthenticateIDRAC(context.Background(), &model.Server{IPAddress: "evil.example", RedfishUser: "root"})
	if res.Success || res.Error == "" || res.ConsoleURL != "" {
		t.Fatalf("res = %+v", res)
	}
}

func TestPreAuthSkipsBMCWhenCredentialsUnreadable(t *testing.T) {
	var hits int
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(bmc.Close)
	res := NewManager([]byte("k")).PreAuthenticateIDRAC(context.Background(), &model.Server{
		IPAddress: hostOf(t, bmc), BMCType: model.BMCIDRAC, RedfishUser: "root", CredentialsUnreadable: true,
	})
	if res.Success || !strings.Contains(res.Error, "decrypted") {
		t.Fatalf("res = %+v", res)
	}
	if hits != 0 {
		t.Fatalf("BMC contacted %d times", hits)
	}
}
