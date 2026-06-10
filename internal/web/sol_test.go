package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticServesXtermAsset(t *testing.T) {
	h := staticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/xterm/xterm.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/xterm/xterm.js = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("xterm.js body is empty")
	}
}
