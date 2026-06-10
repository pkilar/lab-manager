# iDRAC KVM Auto-Login Reverse Proxy — Design (Phase 2)

Status: approved-pending-review
Date: 2026-06-10
Author: Paul Kilar (with Claude)
Depends on: Phase 1 SOL console (`2026-06-09-sol-serial-console-design.md`), iDRAC console-auth findings (`project_idrac_console_auth` memory)

## Context

Cross-origin auto-login into the iDRAC web console is impossible client-side: the
iDRAC SPA's session is an HttpOnly `-http-session-` cookie paired with per-login
`ST1/ST2` tokens it reads from the `/data/login` response `forwardUrl`; a foreign
web origin can neither read those tokens nor inject them. The fix is to make the
iDRAC **same-origin** by reverse-proxying it through lab-manager, so the browser
talks only to lab-manager and lab-manager relays to the iDRAC from a single IP —
which keeps the iDRAC's cookie + source-IP binding consistent and lets lab-manager
perform the login server-side.

Phase 1 shipped the SOL serial console (the reliable text fallback). This phase
adds the graphical KVM auto-login proxy.

## Goals

- One-click: a "KVM" button on an iDRAC row opens the iDRAC web UI **already
  logged in**, in the browser, with the HTML5 Virtual Console reachable.
- The iDRAC's root session token is never exposed to the browser.
- Reuse the existing Traefik `*.pi.home.kilar.net` cert and wildcard DNS; the only
  infra change is one Traefik router rule.
- Feature-flagged off by default; no behavior change when disabled.
- SOL remains the guaranteed fallback.

## Non-goals

- Non-iDRAC vendors (Supermicro/iLO have different login flows; SOL covers them).
- The docker-compose / LAN deploy (no Traefik, no per-host TLS) — proxy is
  Swarm/Traefik-only, mirroring how WoL is compose-only.
- Rewriting the iDRAC SPA's HTML/JS bodies (the subdomain scheme makes absolute
  paths resolve correctly, so only header-level rewriting is needed).
- Multi-replica session sharing (the deploy is a single pinned replica; the
  server-side session map is in-memory and lost on restart — the user re-clicks
  KVM, which re-runs the handshake).

## Decisions (locked during brainstorming)

- **Addressing:** `idrac-<id>.pi.home.kilar.net` — one label deep, so the existing
  one-label wildcard cert `*.pi.home.kilar.net` covers it and the existing
  wildcard DNS already resolves it. (Not `…​.lab.pi…`, which is two labels and the
  cert would not cover.)
- **UX:** a **separate "KVM" button** on iDRAC rows (shown only when the proxy is
  enabled), alongside the existing "Console" (manual page) and "📟 Serial" (SOL).
- **iDRAC session handling:** **server-side** — lab-manager holds the iDRAC
  `-http-session-` value in a server-side session map and injects it upstream; the
  browser holds only an opaque proxy-session cookie.
- **Self-contained:** lab-manager is the reverse proxy (Traefik just routes
  `idrac-*` → lab-manager, which resolves each iDRAC's IP from its own DB).
- **Feature flag:** `LAB_MANAGER_BMC_PROXY_DOMAIN` (e.g. `pi.home.kilar.net`).
  Unset ⇒ entire feature off.

## Architecture: one binary, two vhost roles

`App.Handler()` gains a **Host dispatch** as the outermost layer:

```
Handler():
  if proxyEnabled && hostIsProxy(r.Host):   // idrac-<id>.<proxy-domain>
        bmcproxy.Handler          // own auth + relay; NO app middleware
  else:
        securityHeaders → limitRequestBody → withSession → withCSRF → routes
```

The proxy path intentionally bypasses `limitRequestBody` (its 1 MiB cap would
break virtual-media / firmware uploads) and the app's `X-Frame-Options: DENY`
(the iDRAC SPA frames itself); the proxy passes the iDRAC's own headers through.

**Why subdomain removes body rewriting:** each iDRAC sits at the root of its own
subdomain, so the SPA's absolute paths (`/restgui`, `/data`, `/sysmgmt`) and its
WebSocket URL (built from `window.location`) resolve to the subdomain → proxy →
iDRAC. Only **headers** need rewriting (`Host`, `Origin`, `Referer`, `Location`,
`Set-Cookie`, injected `Cookie`).

## The auto-login handshake

The iDRAC only ever sees lab-manager's IP (the browser never talks to it
directly), so cookie + source-IP binding stay consistent.

1. **Initiate (main host):** the KVM button → `GET /server/<id>/kvm` (behind
   `requireLogin`). It verifies the server is an iDRAC with creds, logs the
   launching user, mints a short-lived signed token (HMAC over
   `server-id:timestamp`, 30 s), and 302-redirects to
   `https://idrac-<id>.<proxy-domain>/__labmgr/auth?token=<t>`.
   - **Note (decided during implementation):** the token is bound to the
     **server id only**, not the user id. The handshake runs on the subdomain
     origin, which has no lab-manager session, so it *cannot verify* a user id —
     binding to it would add no enforceable control. The launching user is
     recorded in the server log at mint time (`slog.Info "KVM proxy launch"`);
     server-id binding still prevents replaying a token against another iDRAC's
     subdomain, and the 30 s TTL + the login-gated initiator bound issuance. All
     authenticated app users are full admins, so user-scoping the token grants
     no additional authorization.
2. **Handshake (proxy host):** `GET /__labmgr/auth?token=<t>`:
   - Verify the token (constant-time, bound to the `<id>` parsed from the Host,
     within 30 s). On failure → redirect to the main app's initiator.
   - Server-side POST the iDRAC `/data/login` (creds from the store) → capture the
     `-http-session-` cookie value and the `forwardUrl` (`index.html?ST1=…,ST2=…`).
     On login failure → an error page with a link back to the dashboard.
   - Create a server-side session: a random 256-bit id → `{serverID,
     idracCookie, expiry (8 h)}`. Set an opaque `bmcproxy` cookie (the id;
     HttpOnly, Secure, `SameSite=Lax`, host-scoped to the subdomain).
   - 302 the browser to the proxied `forwardUrl` (`/index.html?ST1=…,ST2=…`).
3. **Relay (proxy host, all other paths):** require a valid `bmcproxy` cookie
   (unknown/expired → 302 to `https://lab.<proxy-domain>/server/<id>/kvm` to
   re-handshake, which itself requires lab-manager login). Then proxy upstream,
   injecting the stored `-http-session-` cookie. The SPA boots authenticated
   (cookie injected upstream + `ST2` it parsed from the URL) and its KVM
   WebSocket rides the same proxy.

## Components — new package `internal/bmcproxy` (stdlib + `crypto/tls` only)

Dependency graph: `model ← store ← bmcproxy ← web` (sits beside `power`/`console`/`sol`).

- **`idrac_login.go`** — `login(ctx, ip, user, pass) (idracCookie, forwardURL string, err error)`:
  server-side POST `/data/login`, parse `<authResult>0` + `forwardUrl`, return the
  `-http-session-` Set-Cookie value. (Distinct from `console.idracLegacyPreAuth`,
  which only needs the auth result, not the cookie/forwardUrl — small, focused.)
- **`session.go`** — the in-memory session store: `map[string]*session` behind a
  `sync.Mutex`, `crypto/rand` ids, TTL expiry with a lazy sweep on access plus a
  periodic GC goroutine. Holds the injectable iDRAC cookie (which `ModifyResponse`
  refreshes if the iDRAC rotates it).
- **`token.go`** — HMAC mint/verify for the 30 s handshake token (same scheme as
  `console.Manager`; ~15 lines, kept local to avoid cross-package coupling — Rule
  of Three not yet met).
- **`proxy.go`** — `Manager` (holds store, secret, proxy-domain, session store)
  and `Handler`:
  - Host parse `idrac-<id>.<domain>` → `id`; reject non-matching / unknown ids.
  - Route `/__labmgr/auth` → handshake; everything else → `serveProxy`.
  - `serveProxy`: build an `httputil.ReverseProxy` per request to the iDRAC
    (`https://<ip>`, `InsecureSkipVerify`, shared transport). **Director** sets
    upstream `Host`/`Origin`/`Referer` to the iDRAC origin, injects the
    `-http-session-` Cookie, and strips the `bmcproxy` cookie. **ModifyResponse**
    rewrites `Location` (`https://<ip>/…` or relative → subdomain), captures and
    strips upstream `Set-Cookie` for `-http-session-` into the session store, and
    leaves the iDRAC's other headers intact. Detect `Upgrade` requests and hand
    them to the WebSocket tunnel instead.
- **`websocket.go`** — `tunnel`: hijack the downstream conn, `tls.Dial` the iDRAC
  (skip-verify), replay the upgrade request with rewritten headers + injected
  cookie, relay the upstream `101`, then bidirectional `io.Copy`. Protocol-agnostic
  (works for the KVM WS and any other Upgrade); no gorilla needed.

## Web-layer wiring

- `cmd/lab-manager/main.go`: read `LAB_MANAGER_BMC_PROXY_DOMAIN`, pass to `web.New`.
- `internal/web/app.go`: construct `*bmcproxy.Manager` when the domain is set;
  add the Host dispatch in `Handler()`.
- `internal/web/kvm.go` (new) — the initiator `GET /server/{id}/kvm` (behind
  `requireLogin(true,…)`): iDRAC + creds + proxy-enabled check, mint token, 302 to
  the subdomain.
- `internal/web/render.go` + `templates/index.html`: a "KVM" button on iDRAC rows,
  shown only when proxy-enabled (new `serverRow.KVMEnabled` bool, set when
  `bmc_type == idrac` and the proxy domain is configured).

## Error handling

| Condition | Behavior |
|-----------|----------|
| Proxy disabled | Host dispatch never routes to proxy; `/server/<id>/kvm` 404s; KVM button hidden. |
| Bad/expired handshake token | 302 to the main initiator (`/server/<id>/kvm`) to re-mint (requires login). |
| iDRAC `/data/login` fails | Small error page on the subdomain with the reason + link back to the dashboard; server-side log line. |
| Missing/expired `bmcproxy` cookie on a relay request | 302 to `https://lab.<proxy-domain>/server/<id>/kvm` (re-handshake). |
| Host id not a known iDRAC | 404. |
| iDRAC unreachable mid-session | upstream error surfaces as a 502 from the proxy; the user re-clicks KVM. |

No silent failures: handshake/login errors are logged server-side and shown to the user.

## Security

- Relay requires a valid server-side-backed `bmcproxy` cookie; no cookie → bounce
  through the login-gated initiator. The handshake token is 30 s, HMAC-bound to
  user + server.
- The iDRAC root session token is held server-side and injected upstream — never
  in the browser or JS.
- The proxy serves only Hosts matching `idrac-<id>.<proxy-domain>` for **known**
  iDRAC server ids; it is not an open proxy.
- TLS to the BMC uses `InsecureSkipVerify` (self-signed), consistent with the rest
  of the app; the browser↔Traefik leg uses the real `*.pi` cert.
- This proxy exposes the full iDRAC web UI (which can power-cycle / reflash) to any
  authenticated lab-manager user — that is the intended capability of an admin
  tool and matches the existing power-control surface.

## Infrastructure delta (minimal)

- **Traefik (v3.6)** — one router in `docker-stack.yml` `deploy.labels`, same
  `lab-manager` service:
  ```
  traefik.http.routers.lab-manager-bmc.rule=HostRegexp(`^idrac-[0-9]+\.pi\.home\.kilar\.net$`)
  traefik.http.routers.lab-manager-bmc.entrypoints=websecure
  traefik.http.routers.lab-manager-bmc.tls=true
  traefik.http.routers.lab-manager-bmc.service=lab-manager
  ```
  (v3 `HostRegexp` takes a Go regexp; reuses the default `*.pi` cert via `tls=true`.)
- **DNS:** none — `*.pi.home.kilar.net` wildcard already resolves to the cluster.
- **App:** set `LAB_MANAGER_BMC_PROXY_DOMAIN=pi.home.kilar.net` in the stack env.
- The app must know its own external host for the relay re-handshake bounce; it
  derives `lab.<proxy-domain>` (matches this deploy: `lab.pi.home.kilar.net`).

## Testing

- **Automated (in-repo), against a fake iDRAC (`httptest.NewTLSServer`)** emulating
  `/data/login` (Set-Cookie + `forwardUrl`), a cookie-protected resource, and a WS
  echo endpoint:
  - Host dispatch: proxy host → proxy; app host → app.
  - Handshake: token mint/verify (expiry + server/user binding); login captures the
    cookie; sets `bmcproxy`; 302s to `forwardUrl`.
  - Relay: no cookie → bounce; valid cookie → upstream receives the injected
    `-http-session-`; `Location` rewriting; upstream `Set-Cookie` rotation captured
    + stripped from the browser response.
  - WebSocket tunnel: round-trips bytes through the proxy to the fake WS.
  - Token/session expiry and unknown-id rejection.
- **Real end-to-end (browser → Traefik → real iDRAC KVM): out-of-band, in the
  deployed cluster** — not reachable from the dev host. Ship behind the flag;
  verify on deploy; iterate on firmware quirks (hardcoded host in the KVM JS, an
  Origin/Referer check the proxy must spoof). **SOL is the fallback throughout.**
- Existing suites stay green (`go vet`, `gofmt -l`, `go test -race ./...`).

## Files changed

- `internal/bmcproxy/{proxy.go,session.go,token.go,idrac_login.go,websocket.go}` (new)
- `internal/bmcproxy/*_test.go` (new — fake-iDRAC tests)
- `internal/web/app.go` — Host dispatch + wiring
- `internal/web/kvm.go` (new) — `/server/{id}/kvm` initiator
- `internal/web/routes.go` — register the initiator
- `internal/web/render.go` + `templates/index.html` — KVM button + `KVMEnabled`
- `cmd/lab-manager/main.go` — read `LAB_MANAGER_BMC_PROXY_DOMAIN`
- `docker-stack.yml` — Traefik `idrac-*` router label + the env var
- `CLAUDE.md`, `README.md` — document the proxy, the flag, and the Traefik rule

## Risks / open questions

- **Real-iDRAC KVM behavior is unverified from here.** The HTML5 vConsole may build
  its WebSocket URL from a value other than `window.location` (e.g. a config blob
  containing the iDRAC IP), or enforce an `Origin`/`Referer` it computes — either
  would need a targeted fix once observed on deploy. Mitigation: the tunnel rewrites
  `Origin`/`Referer`; if the JS hardcodes the IP, a narrow body-rewrite for that one
  asset may be needed (added only if observed). This is the main reason the feature
  ships flagged-off with a deploy-time verification step.
- **In-memory sessions** are lost on restart/redeploy (single replica) — acceptable;
  the user re-clicks KVM.
- **Idle/half-open sockets** on the KVM WS — same class as the SOL keepalive
  fast-follow; bounded, revisit if needed.

## Forward note

If the KVM JS turns out to hardcode the iDRAC IP (worst case), the fallback is a
single targeted response-body rewrite for that asset only — still far short of
full SPA rewriting, because the subdomain handles everything else.
