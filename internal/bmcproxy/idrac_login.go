package bmcproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const idracSessionCookie = "-http-session-"

// proxyTransport reaches BMCs which present self-signed certs. Shared so its
// connection pool is reused across the login and the relay. ResponseHeaderTimeout
// bounds a hung iDRAC on the relay path (it caps time-to-first-header only, so it
// does not interrupt the KVM WebSocket once the 101 upgrade has come back).
var proxyTransport = &http.Transport{
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // BMCs use self-signed certs
	ResponseHeaderTimeout: 30 * time.Second,
}

// loginClient never follows redirects: /data/login returns 200 + XML, and we
// must read the Set-Cookie/forwardUrl off that exact response.
var loginClient = &http.Client{
	Transport:     proxyTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var (
	authResultPattern = regexp.MustCompile(`<authResult>(\d+)</authResult>`)
	forwardURLPattern = regexp.MustCompile(`<forwardUrl>([^<]*)</forwardUrl>`)
	// The iDRAC reports WHY a login was refused in these two fields. Without
	// them a bare authResult code is unactionable — notably it cannot
	// distinguish "wrong password" from "web session table full", which
	// present identically but need opposite fixes.
	errorMsgPattern     = regexp.MustCompile(`<errorMsg>([^<]*)</errorMsg>`)
	blockingTimePattern = regexp.MustCompile(`<blockingTime>(\d+)</blockingTime>`)
)

// loginFailure renders an actionable error from a non-zero authResult, folding
// in the iDRAC's own errorMsg and any active IP-block backoff.
func loginFailure(code string, body []byte) error {
	detail := ""
	if m := errorMsgPattern.FindSubmatch(body); m != nil && len(m[1]) > 0 {
		detail = ": " + html.UnescapeString(string(m[1]))
	}
	if m := blockingTimePattern.FindSubmatch(body); m != nil && string(m[1]) != "0" {
		detail += fmt.Sprintf(" (iDRAC is rate-limiting this client for %ss)", m[1])
	}
	return fmt.Errorf("iDRAC login failed (authResult %s)%s", code, detail)
}

// idracLogin performs the iDRAC web login server-side and returns the
// "-http-session-=..." cookie to inject upstream plus the SPA forward URL
// ("index.html?ST1=...,ST2=...").
func idracLogin(ctx context.Context, ip, user, pass string) (cookie, forwardURL string, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	form := strings.NewReader(url.Values{"user": {user}, "password": {pass}}.Encode())
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://"+ip+"/data/login", form)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := loginClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	// Check the status before scanning the body: without this, a 404 (endpoint
	// gone on newer firmware) or a 500 HTML error page both surface as the
	// useless "response unparseable", hiding what actually went wrong.
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("iDRAC login returned HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := authResultPattern.FindSubmatch(body)
	if m == nil {
		return "", "", errors.New("iDRAC login response unparseable")
	}
	if string(m[1]) != "0" {
		return "", "", loginFailure(string(m[1]), body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == idracSessionCookie {
			cookie = c.Name + "=" + c.Value
			break
		}
	}
	if cookie == "" {
		return "", "", errors.New("iDRAC login set no session cookie")
	}
	fm := forwardURLPattern.FindSubmatch(body)
	if fm == nil {
		return "", "", errors.New("iDRAC login response had no forwardUrl")
	}
	return cookie, string(fm[1]), nil
}
