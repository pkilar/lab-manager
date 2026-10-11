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
	wolEnabled, err := envBool("WOL_ENABLED", false)
	if err != nil {
		return err
	}
	strict, err := envBool("LAB_MANAGER_STRICT_CONFIG", false)
	if err != nil {
		return err
	}
	bmcProxyDomain := os.Getenv("LAB_MANAGER_BMC_PROXY_DOMAIN")
	if err := checkStrictConfig(strict,
		os.Getenv("LAB_MANAGER_SECRET_KEY"), bmcProxyDomain,
		os.Getenv("LAB_MANAGER_ENCRYPTION_KEY")); err != nil {
		return err
	}
	if bmcProxyDomain == "" {
		slog.Warn("BMC proxy disabled: LAB_MANAGER_BMC_PROXY_DOMAIN is empty " +
			"(no KVM auto-login; Console falls back to showing credentials)")
	}

	// The dir holds the DB and the encryption key; owner-only (MkdirAll leaves an
	// existing dir's mode alone).
	const instanceDir = "instance"
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
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
		// The whole stop must fit Docker's default 10s grace period before
		// SIGKILL, so drain requests and release BMC state (SOL payloads, iDRAC
		// sessions -- which Shutdown doesn't track) concurrently, within 8s.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		released := make(chan struct{})
		go func() {
			app.Close()
			close(released)
		}()
		err := srv.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			// Still-running handlers (e.g. /check-all-servers against dead BMCs)
			// are cut off; that's an expected way to stop, not a failure.
			slog.Warn("graceful shutdown timed out; closing remaining connections")
			err = srv.Close()
		}
		select {
		case <-released:
		case <-shutdownCtx.Done():
			slog.Warn("BMC session cleanup unfinished at shutdown deadline; BMCs will time those sessions out")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// minSecretKeyLen is the shortest LAB_MANAGER_SECRET_KEY a strict deploy will
// accept. The documented recipe is `openssl rand -hex 32` (64 chars); 32 leaves
// room for other encodings of 128+ bits while still rejecting a placeholder.
const minSecretKeyLen = 32

// checkStrictConfig refuses to start when a deployment that declares itself
// production has configuration that would otherwise degrade silently.
//
// This exists because `docker stack deploy` does NOT read .env: it interpolates
// ${VAR} from the deploying shell, and an unset variable collapses to "". A CLI
// redeploy that forgets to export them therefore starts a perfectly healthy
// container which has quietly lost the BMC proxy domain (KVM auto-login
// disappears, Console silently reverts to copy/paste) and the session key (a new
// random one per boot, so every session dies on restart).
//
// It also rejects values that are present but unusable, which is the failure
// mode that actually survived longest in production: a 6-character placeholder
// sat in both key variables for three months. Empty was caught; wrong was not.
//
// The flag is deliberately set as a LITERAL in docker-stack.yml rather than as
// ${LAB_MANAGER_STRICT_CONFIG}, so it cannot be erased by the very mistake it
// exists to catch. docker-compose.yml leaves it unset, so development and the
// host-networked deploy (where the proxy genuinely cannot work) are unaffected.
func checkStrictConfig(strict bool, secretKey, bmcProxyDomain, encryptionKey string) error {
	if !strict {
		return nil
	}
	var problems []string
	switch {
	case secretKey == "":
		problems = append(problems,
			"LAB_MANAGER_SECRET_KEY is empty (sessions would not survive a restart)")
	case len(secretKey) < minSecretKeyLen:
		// It signs session cookies and console tokens, so a short key is not a
		// style question: it is brute-forceable offline from one cookie.
		problems = append(problems, fmt.Sprintf(
			"LAB_MANAGER_SECRET_KEY is only %d characters, need at least %d "+
				"(generate with `openssl rand -hex 32`) - it signs session cookies "+
				"and console tokens, so a short one can be brute-forced offline",
			len(secretKey), minSecretKeyLen))
	}
	if bmcProxyDomain == "" {
		problems = append(problems,
			"LAB_MANAGER_BMC_PROXY_DOMAIN is empty (iDRAC KVM auto-login would be disabled)")
	}
	// An EMPTY encryption key is correct and expected: the key belongs on the
	// data volume at instance/.encryption_key. A malformed one is the trap -
	// LoadEncryptionKey rejects it and falls back to the file, so the variable
	// looks configured while doing nothing but logging one ERROR per start.
	if encryptionKey != "" {
		if _, err := secret.NewFernet([]byte(encryptionKey)); err != nil {
			problems = append(problems, fmt.Sprintf(
				"LAB_MANAGER_ENCRYPTION_KEY is set but is not a valid Fernet key (%v); "+
					"it would be ignored in favour of instance/.encryption_key - leave it unset",
				err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("LAB_MANAGER_STRICT_CONFIG is on but the configuration is not usable:\n  - %s\n"+
		"`docker stack deploy` does not read .env - export these in the deploying shell "+
		"or set them in the Portainer stack environment, then redeploy",
		strings.Join(problems, "\n  - "))
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

// envBool parses a boolean env var. Unknown values are an error rather than
// false: a typo like LAB_MANAGER_STRICT_CONFIG=ture must not silently disable
// the guard it was meant to enable.
func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return def, nil
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %s=%q (want true/false, 1/0, yes/no, on/off)", key, v)
	}
}
