package bmcproxy

import (
	"testing"
)

func TestIDRACLoginCapturesCookieAndForwardURL(t *testing.T) {
	idrac := newFakeIDRAC(t)
	cookie, forward, err := idracLogin(t.Context(), hostport(idrac), "root", "calvin")
	if err != nil {
		t.Fatalf("idracLogin: %v", err)
	}
	if cookie != "-http-session-="+idracSessionValue {
		t.Fatalf("cookie = %q, want -http-session-=%s", cookie, idracSessionValue)
	}
	if forward != "index.html?ST1=aaa,ST2=bbb" {
		t.Fatalf("forward = %q", forward)
	}
}

func TestIDRACLoginRejectsBadCreds(t *testing.T) {
	idrac := newFakeIDRAC(t)
	if _, _, err := idracLogin(t.Context(), hostport(idrac), "root", "wrong"); err == nil {
		t.Fatal("expected error on bad credentials")
	}
}
