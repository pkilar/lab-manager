package bmcproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const idracSessionCookie = "-http-session-"

// proxyTransport reaches BMCs which present self-signed certs. Shared so its
// connection pool is reused across the login and the relay.
var proxyTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // BMCs use self-signed certs
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
)

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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := authResultPattern.FindSubmatch(body)
	if m == nil {
		return "", "", errors.New("iDRAC login response unparseable")
	}
	if string(m[1]) != "0" {
		return "", "", fmt.Errorf("iDRAC login failed (authResult %s)", m[1])
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
