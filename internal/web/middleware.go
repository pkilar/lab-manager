package web

import "net/http"

// maxRequestBody caps request bodies. The forms here are tiny; this only stops a
// malformed or hostile client from forcing unbounded reads during parsing.
const maxRequestBody = 1 << 20 // 1 MiB

// securityHeaders sets conservative response headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY") // legacy browsers; CSP frame-ancestors below is the modern form
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		// The browser default, made explicit: cross-origin navigations (e.g. from
		// the console launch page, whose URL carries ?token=, to a BMC) send only
		// the origin. Deliberately not no-referrer/same-origin: the Supermicro
		// launch page auto-POSTs a login form to the BMC and some BMC CGIs
		// require a Referer header.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// limitRequestBody bounds the request body on unsafe methods before any handler
// or middleware reads it.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		default:
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}
