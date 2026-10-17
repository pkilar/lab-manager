package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

const testMCPToken = "0123456789abcdef0123456789abcdef-web-test"

// withMCP turns the MCP endpoint on through the same constructor New uses.
func withMCP(a *App) { a.mcp = a.mcpHandler(testMCPToken) }

// mcpPost sends one JSON-RPC message to /mcp the way a streamable-HTTP MCP
// client does. An empty token sends no Authorization header.
func mcpPost(t *testing.T, c *http.Client, base, token, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+mcpPath, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", mcpPath, err)
	}
	return resp, readBody(t, resp)
}

const mcpToolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

func mcpToolCall(name string) string {
	return `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
}

// With no token configured /mcp is a plain 404, not the CSRF layer's 400, which
// would send someone debugging a client after the wrong problem.
func TestMCPEndpointOffByDefault(t *testing.T) {
	srv, c, _ := testServer(t)
	resp, _ := mcpPost(t, c, srv.URL, testMCPToken, mcpToolsList)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /mcp with the feature off: status %d, want 404", resp.StatusCode)
	}
}

// An MCP client has no session cookie and no CSRF token; the bearer token alone
// must get it through, with the app's security headers still applied.
func TestMCPEndpointSkipsSessionAndCSRF(t *testing.T) {
	srv, c, _, _ := testServerApp(t, withMCP)
	resp, body := mcpPost(t, c, srv.URL, testMCPToken, mcpToolsList)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list: status %d, body %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"name":"list_servers"`) {
		t.Errorf("tools/list response lacks list_servers: %s", body)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q: the endpoint skipped securityHeaders", got)
	}
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Errorf("MCP response set a cookie (%q): it went through the session layer", got)
	}
}

// A logged-in browser session is not MCP auth: otherwise any page the user
// visits could drive power control with their cookie.
func TestMCPEndpointIgnoresSessionCookie(t *testing.T) {
	srv, c, _, _ := testServerApp(t, withMCP)
	readyUser(t, srv.URL, c)
	for _, token := range []string{"", "wrong-token-0123456789abcdef0123456789"} {
		resp, _ := mcpPost(t, c, srv.URL, token, mcpToolsList)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q with a valid session cookie: status %d, want 401", token, resp.StatusCode)
		}
	}
}

// End to end through the real store and power controller: the inventory comes
// back without a single credential, and a power command reaches the controller
// (a server with nothing configured fails fast, with no network involved).
func TestMCPToolsAgainstRealStore(t *testing.T) {
	srv, c, st, _ := testServerApp(t, withMCP)
	secrets := []string{"rf-user-7c1d", "rf-pass-9e2a", "ipmi-user-3b8f", "ipmi-pass-5d4c", "aa:bb:cc:dd:ee:01"}
	if err := st.CreateServer(&model.Server{
		Name: "r630", IPAddress: "192.0.2.10", BMCType: model.BMCIDRAC, Status: "On",
		RedfishUser: secrets[0], RedfishPassword: secrets[1], IPMIUser: secrets[2], IPMIPassword: secrets[3],
		MACAddress: secrets[4],
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServer(&model.Server{Name: "bare", IPAddress: "192.0.2.11", BMCType: model.BMCGeneric, Status: "Unknown"}); err != nil {
		t.Fatal(err)
	}

	resp, body := mcpPost(t, c, srv.URL, testMCPToken, mcpToolCall("list_servers"))
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `"isError":true`) {
		t.Fatalf("list_servers: status %d, body %s", resp.StatusCode, body)
	}
	for _, want := range []string{`"name":"r630"`, `"power_control":"redfish"`, `"name":"bare"`, `"power_control":"none"`} {
		if !strings.Contains(body, want) {
			t.Errorf("list_servers response lacks %s: %s", want, body)
		}
	}
	for _, s := range secrets {
		if strings.Contains(body, s) {
			t.Errorf("list_servers leaked %q", s)
		}
	}

	resp, body = mcpPost(t, c, srv.URL, testMCPToken,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"power_off","arguments":{"server_id":2}}}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"isError":true`) ||
		!strings.Contains(body, "No authentication credentials configured") {
		t.Fatalf("power_off on an unconfigured server: status %d, body %s", resp.StatusCode, body)
	}
}
