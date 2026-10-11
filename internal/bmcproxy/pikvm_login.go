package bmcproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const pikvmSessionCookie = "auth_token"

// pikvmLogin performs the PiKVM (kvmd) web login server-side. It returns the
// "auth_token=..." cookie to inject upstream, or "" when PiKVM auth is disabled
// (kvmd then answers 200 with no cookie and none is needed). forwardURL is
// always "": PiKVM lands via vendor.targets.
func pikvmLogin(ctx context.Context, ip, user, pass string) (cookie, forwardURL string, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	form := url.Values{"user": {user}, "passwd": {pass}}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://"+ip+"/api/auth/login", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := loginClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusUnauthorized:
		return "", "", errors.New("PiKVM login failed: invalid credentials")
	default:
		return "", "", fmt.Errorf("PiKVM login returned HTTP %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == pikvmSessionCookie && c.Value != "" {
			return c.Name + "=" + c.Value, "", nil
		}
	}
	return "", "", nil
}

// pikvmSessionValid asks kvmd whether cookie still authenticates (the endpoint
// nginx itself uses for auth_request). Any failure reads as invalid, which
// only costs a fresh login.
func pikvmSessionValid(ctx context.Context, ip, cookie string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+ip+"/api/auth/check", nil)
	if err != nil {
		return false
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := loginClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
