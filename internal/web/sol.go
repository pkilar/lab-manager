package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Keepalive and bounds for the SOL socket. Without them a client that vanishes
// without a FIN leaves the read pump blocked forever, pinning ipmitool and the
// BMC's single SOL payload, and a stalled client can block a write forever.
type solTimings struct {
	pongWait   time.Duration // silence tolerated before the read fails
	pingPeriod time.Duration // must stay well under pongWait
	writeWait  time.Duration
}

// defaultSOLTimings are the production values; App carries its own copy so a
// test can shrink them before the server starts.
var defaultSOLTimings = solTimings{pongWait: 60 * time.Second, pingPeriod: 25 * time.Second, writeWait: 10 * time.Second}

// solReadLimit bounds one inbound frame. xterm sends a paste as a single frame,
// so this must comfortably exceed a realistic paste while still capping hostile
// frames.
const solReadLimit = 64 << 10

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
	conn.SetReadLimit(solReadLimit) // keystrokes are tiny but a paste is one frame; bound hostile frames
	tm := a.solTimings
	_ = conn.SetReadDeadline(time.Now().Add(tm.pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(tm.pongWait))
	})

	sess, err := a.sol.Start(r.Context(), s)
	if err != nil {
		slog.Error("SOL session start", "server_id", id, "err", err)
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\n"+err.Error()+"\r\n"))
		return
	}
	defer func() { _ = sess.Close() }()

	// Pinger: the client's pong (answered automatically by browsers) extends the
	// read deadline. WriteControl may run concurrently with the write pump. A
	// ping failure just ends the pinger; the read deadline then tears us down.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(tm.pingPeriod)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(tm.writeWait)) != nil {
					return
				}
			}
		}
	}()

	// Read pump: browser keystrokes → ipmitool stdin. Closing the session on
	// exit unblocks the write pump.
	go func() {
		defer func() { _ = sess.Close() }()
		for {
			_, data, rerr := conn.ReadMessage()
			if rerr != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(tm.pongWait))
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
			// Binary, not Text: serial output is arbitrary bytes (CP437 BIOS
			// screens, a UTF-8 rune split across reads), and browsers fail the
			// connection on a text frame that isn't valid UTF-8. The page sets
			// binaryType='arraybuffer' and xterm decodes UTF-8 across writes.
			_ = conn.SetWriteDeadline(time.Now().Add(tm.writeWait))
			if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
