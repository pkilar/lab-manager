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
		h.Set("X-Frame-Options", "DENY")
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
