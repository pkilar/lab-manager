package bmcproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// The iDRAC's login CGI is order-sensitive: it answers authResult 1 to a body
// that puts password before user, even when the credentials are correct.
// url.Values.Encode() sorts keys alphabetically and so always produced exactly
// that rejected form, which broke every server-side login. Assert the wire
// format directly rather than relying on the fixture alone.
func TestIDRACLoginSendsUserBeforePassword(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<root><authResult>1</authResult><forwardUrl>index.html</forwardUrl></root>`)
	}))
	t.Cleanup(srv.Close)

	_, _, _ = idracLogin(t.Context(), strings.TrimPrefix(srv.URL, "https://"), "root", "pa ss+word")
	if !strings.HasPrefix(got, "user=root&password=") {
		t.Fatalf("login body = %q, want it to start with user=root&password=", got)
	}
	// A space must go out as %20, not "+": this parser is demonstrably
	// non-standard, and %20 decodes correctly under either interpretation.
	if !strings.Contains(got, "pa%20ss%2Bword") {
		t.Fatalf("login body = %q, want the space as %%20 and + as %%2B", got)
	}
}

// A bare authResult code cannot distinguish "wrong password" from "session
// table full" — opposite fixes. The iDRAC says which in errorMsg/blockingTime,
// so the error must carry them. Body shape is copied from a real iDRAC8
// (firmware ~2.6x) /data/login response.
func TestIDRACLoginSurfacesErrorMsgAndBlocking(t *testing.T) {
	const body = `<?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> ` +
		`<authResult>7</authResult> <blockingTime>30</blockingTime> ` +
		`<forwardUrl>index.html</forwardUrl> <errorMsg>Maximum sessions reached</errorMsg></root>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	_, _, err := idracLogin(t.Context(), strings.TrimPrefix(srv.URL, "https://"), "root", "calvin")
	if err == nil {
		t.Fatal("expected an error on authResult 7")
	}
	for _, want := range []string{"authResult 7", "Maximum sessions reached", "30s"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
}

// A non-200 (endpoint missing on newer firmware, or an HTML error page) must
// name the status code. It previously fell through to the body regex and
// reported "response unparseable", which hid the real failure.
func TestIDRACLoginReportsHTTPStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html>not found</html>", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, _, err := idracLogin(t.Context(), strings.TrimPrefix(srv.URL, "https://"), "root", "calvin")
	if err == nil {
		t.Fatal("expected an error on HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %q, want it to name the 404 status", err)
	}
}

func TestIDRACLoginRejectsBadCreds(t *testing.T) {
	idrac := newFakeIDRAC(t)
	if _, _, err := idracLogin(t.Context(), hostport(idrac), "root", "wrong"); err == nil {
		t.Fatal("expected error on bad credentials")
	}
}
