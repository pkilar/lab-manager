package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

// solUpgrader upgrades the SOL WebSocket. CheckOrigin enforces a same-host
// Origin: the WS handshake is a GET and bypasses the form-based CSRF middleware,
// so this is the cross-site-WebSocket-hijacking guard.
var solUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false // browsers always send Origin on WS upgrades
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

// handleSOLLaunch renders the xterm.js page. Creds stay server-side; the page
// only needs the id + name.
func (a *App) handleSOLLaunch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	a.renderConsole(w, "console_sol", consoleSOLData{
		ServerID: s.ID, ServerName: s.Name, SOLInstance: s.SOLInstanceOrDefault(),
	})
}

// handleSOLSocket upgrades to a WebSocket and bridges it to an SOL session:
// a write pump (BMC output → socket) on this goroutine and a read pump
// (keystrokes → ipmitool stdin) on a second goroutine. Only the write pump
// writes to the socket (gorilla requires a single writer).
func (a *App) handleSOLSocket(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	conn, err := solUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the HTTP error (e.g. 403 on bad Origin)
	}
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(4096) // terminal keystrokes are tiny; bound hostile frames

	sess, err := a.sol.Start(r.Context(), s)
	if err != nil {
		slog.Error("SOL session start", "server_id", id, "err", err)
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\n"+err.Error()+"\r\n"))
		return
	}
	defer func() { _ = sess.Close() }()

	// Read pump: browser keystrokes → ipmitool stdin. Closing the session on
	// exit unblocks the write pump.
	go func() {
		defer func() { _ = sess.Close() }()
		for {
			_, data, rerr := conn.ReadMessage()
			if rerr != nil {
				return
			}
			if _, werr := sess.Stdin.Write(data); werr != nil {
				return
			}
		}
	}()

	// Write pump: ipmitool output → browser. Returns on EOF / socket error.
	buf := make([]byte, 4096)
	for {
		n, rerr := sess.Output.Read(buf)
		if n > 0 {
			if werr := conn.WriteMessage(websocket.TextMessage, buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
