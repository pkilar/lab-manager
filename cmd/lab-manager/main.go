// Command lab-manager is a web application for managing physical servers via
// IPMI, Redfish, and Wake-on-LAN. It serves a fixed set of routes backed by a
// SQLite schema, stores credentials encrypted on disk (Fernet) and hashes
// passwords with scrypt, with all templates embedded into a single static
// binary.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "time/tzdata" // embed the zoneinfo DB so local-time formatting works anywhere

	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
	"github.com/pkilar/lab-manager/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	const instanceDir = "instance"
	if err := os.MkdirAll(instanceDir, 0o755); err != nil {
		return err
	}

	secretKey, err := loadSecretKey()
	if err != nil {
		return err
	}

	keyB64, err := secret.LoadEncryptionKey(instanceDir)
	if err != nil {
		return err
	}
	cipher, err := secret.NewFernet(keyB64)
	if err != nil {
		return err
	}

	st, err := store.Open(filepath.Join(instanceDir, "servers.db"), cipher)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.InitDefaultUser(); err != nil {
		return err
	}

	wolEnabled := envBool("WOL_ENABLED", false)
	app, err := web.New(st, secretKey, wolEnabled)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              ":5000",
		Handler:           app.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout is intentionally unset: /check-all-servers can legitimately
		// take minutes when several BMCs are slow or unreachable (each protocol
		// call has its own 30s timeout).
		IdleTimeout: 120 * time.Second,
	}

	log.Printf("INFO: lab-manager listening on :5000 (wol_enabled=%v)", wolEnabled)
	return srv.ListenAndServe()
}

// loadSecretKey reads LAB_MANAGER_SECRET_KEY, or generates an ephemeral key (with a
// warning) when unset — in which case session cookies are signed with a key that
// changes each boot, so sessions don't survive a restart.
func loadSecretKey() ([]byte, error) {
	if k := os.Getenv("LAB_MANAGER_SECRET_KEY"); k != "" {
		return []byte(k), nil
	}
	log.Printf("WARNING: LAB_MANAGER_SECRET_KEY not set! Using a random key (sessions won't persist across restarts)")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b)), nil
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}
