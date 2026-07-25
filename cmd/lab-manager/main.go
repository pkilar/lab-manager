// Command lab-manager is a web application for managing physical servers via
// IPMI, Redfish, and Wake-on-LAN. It serves a fixed set of routes backed by a
// SQLite schema, stores credentials encrypted on disk (Fernet) and hashes
// passwords with scrypt, with all templates embedded into a single static
// binary.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "time/tzdata" // embed the zoneinfo DB so local-time formatting works anywhere

	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
	"github.com/pkilar/lab-manager/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	// Validate configuration before anything with side effects: a strict deploy
	// that is missing settings should fail without having created a database,
	// an encryption key or a default admin user.
	wolEnabled := envBool("WOL_ENABLED", false)
	bmcProxyDomain := os.Getenv("LAB_MANAGER_BMC_PROXY_DOMAIN")
	if err := checkStrictConfig(envBool("LAB_MANAGER_STRICT_CONFIG", false),
		os.Getenv("LAB_MANAGER_SECRET_KEY"), bmcProxyDomain); err != nil {
		return err
	}
	if bmcProxyDomain == "" {
		slog.Warn("BMC proxy disabled: LAB_MANAGER_BMC_PROXY_DOMAIN is empty " +
			"(no KVM auto-login; Console falls back to showing credentials)")
	}

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
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("closing store", "err", err)
		}
	}()

	if err := st.InitDefaultUser(); err != nil {
		return err
	}

	app, err := web.New(st, secretKey, wolEnabled, bmcProxyDomain)
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

	// Serve until a shutdown signal, then drain in-flight requests gracefully so
	// no SQLite write is interrupted mid-request.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("lab-manager listening", "addr", ":5000", "wol_enabled", wolEnabled, "bmc_proxy_domain", bmcProxyDomain)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stop() // restore default behaviour so a second signal force-quits
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// checkStrictConfig refuses to start when a deployment that declares itself
// production is missing configuration that would otherwise degrade silently.
//
// This exists because `docker stack deploy` does NOT read .env: it interpolates
// ${VAR} from the deploying shell, and an unset variable collapses to "". A CLI
// redeploy that forgets to export them therefore starts a perfectly healthy
// container which has quietly lost the BMC proxy domain (KVM auto-login
// disappears, Console silently reverts to copy/paste) and the session key (a new
// random one per boot, so every session dies on restart). Both previously
// announced themselves only as log lines that are easy to miss.
//
// The flag is deliberately set as a LITERAL in docker-stack.yml rather than as
// ${LAB_MANAGER_STRICT_CONFIG}, so it cannot be erased by the very mistake it
// exists to catch. docker-compose.yml leaves it unset, so development and the
// host-networked deploy (where the proxy genuinely cannot work) are unaffected.
func checkStrictConfig(strict bool, secretKey, bmcProxyDomain string) error {
	if !strict {
		return nil
	}
	var missing []string
	if secretKey == "" {
		missing = append(missing, "LAB_MANAGER_SECRET_KEY (sessions would not survive a restart)")
	}
	if bmcProxyDomain == "" {
		missing = append(missing, "LAB_MANAGER_BMC_PROXY_DOMAIN (iDRAC KVM auto-login would be disabled)")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("LAB_MANAGER_STRICT_CONFIG is on but required settings are empty:\n  - %s\n"+
		"`docker stack deploy` does not read .env — export these in the deploying shell "+
		"or set them in the Portainer stack environment, then redeploy",
		strings.Join(missing, "\n  - "))
}

// loadSecretKey reads LAB_MANAGER_SECRET_KEY, or generates an ephemeral key (with a
// warning) when unset — in which case session cookies are signed with a key that
// changes each boot, so sessions don't survive a restart.
func loadSecretKey() ([]byte, error) {
	if k := os.Getenv("LAB_MANAGER_SECRET_KEY"); k != "" {
		return []byte(k), nil
	}
	slog.Warn("LAB_MANAGER_SECRET_KEY not set; using a random key (sessions won't persist across restarts)")
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
