package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A realistic key: `openssl rand -hex 32`, the recipe the docs give.
const goodSecretKey = "9f2c1e7a4b8d6035fe1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70"

// A valid Fernet key: urlsafe-base64 of 32 bytes.
const goodFernetKey = "VTfdkyi4hZ3WvGv84jig3XyW_OUl6ovpe1ZU7UUIgRM="

// checkStrictConfig turns a silently-degraded production deploy into a startup
// failure. The cases below are the ones that actually occurred: a
// `docker stack deploy` without the environment exported collapses every
// ${VAR} to "", and - the one that survived three months undetected - a
// 6-character placeholder left in both key variables, which is not empty and so
// passed the original emptiness-only check.
func TestCheckStrictConfig(t *testing.T) {
	cases := []struct {
		name           string
		strict         bool
		secretKey      string
		bmcProxyDomain string
		encryptionKey  string
		wantErr        bool
		wantMentions   []string
	}{
		{
			name:   "lenient deploy tolerates everything missing",
			strict: false,
			// The host-networked compose deploy cannot run the proxy at all, and
			// a throwaway run legitimately has no secret key. Must still start.
			wantErr: false,
		},
		{
			name: "strict deploy fully configured", strict: true,
			secretKey: goodSecretKey, bmcProxyDomain: "pi.home.kilar.net", wantErr: false,
		},
		{
			// The recommended production shape: the Fernet key lives on the data
			// volume, so the variable is deliberately absent. Must not error.
			name: "strict deploy with the encryption key left unset", strict: true,
			secretKey: goodSecretKey, bmcProxyDomain: "pi.home.kilar.net",
			encryptionKey: "", wantErr: false,
		},
		{
			name: "strict deploy with an explicit valid encryption key", strict: true,
			secretKey: goodSecretKey, bmcProxyDomain: "pi.home.kilar.net",
			encryptionKey: goodFernetKey, wantErr: false,
		},
		{
			name: "strict deploy that lost the proxy domain", strict: true,
			secretKey: goodSecretKey, bmcProxyDomain: "",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_BMC_PROXY_DOMAIN", "stack deploy"},
		},
		{
			name: "strict deploy that lost the secret key", strict: true,
			secretKey: "", bmcProxyDomain: "pi.home.kilar.net",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_SECRET_KEY", "empty"},
		},
		{
			name: "strict deploy that lost the whole environment", strict: true,
			secretKey: "", bmcProxyDomain: "",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_SECRET_KEY", "LAB_MANAGER_BMC_PROXY_DOMAIN"},
		},
		{
			// The real incident: a 6-character placeholder in both keys. Neither
			// is empty, so the emptiness-only guard let it through.
			name: "strict deploy with placeholder keys (the incident)", strict: true,
			secretKey: "abc123", bmcProxyDomain: "pi.home.kilar.net", encryptionKey: "abc123",
			wantErr: true,
			wantMentions: []string{
				"LAB_MANAGER_SECRET_KEY", "6 characters", "openssl rand -hex 32",
				"LAB_MANAGER_ENCRYPTION_KEY", "instance/.encryption_key",
			},
		},
		{
			// One character short must still fail, or the boundary is decorative.
			name: "strict deploy with a secret key one char under the minimum", strict: true,
			secretKey: strings.Repeat("a", minSecretKeyLen-1), bmcProxyDomain: "pi.home.kilar.net",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_SECRET_KEY", "at least 32"},
		},
		{
			name: "strict deploy with a secret key exactly at the minimum", strict: true,
			secretKey: strings.Repeat("a", minSecretKeyLen), bmcProxyDomain: "pi.home.kilar.net",
			wantErr: false,
		},
		{
			// Well-formed base64 of the WRONG length is the dangerous near-miss:
			// it looks like a key and is not one.
			name: "strict deploy with a base64 key of the wrong length", strict: true,
			secretKey: goodSecretKey, bmcProxyDomain: "pi.home.kilar.net",
			encryptionKey: "c2hvcnRrZXk=", // 9 bytes, not 32
			wantErr:       true, wantMentions: []string{"LAB_MANAGER_ENCRYPTION_KEY", "32 bytes"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStrictConfig(tc.strict, tc.secretKey, tc.bmcProxyDomain, tc.encryptionKey)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkStrictConfig(%v, %q, %q, %q) error = %v, wantErr %v",
					tc.strict, tc.secretKey, tc.bmcProxyDomain, tc.encryptionKey, err, tc.wantErr)
			}
			for _, want := range tc.wantMentions {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should name %q so the fix is obvious", err, want)
				}
			}
		})
	}
}

// The guard must never leak a key into logs: the operator pastes these errors
// into chat and tickets. It reports lengths and formats, never values.
func TestCheckStrictConfigDoesNotEchoSecrets(t *testing.T) {
	const secret = "hunter2placeholder"
	err := checkStrictConfig(true, secret, "pi.home.kilar.net", secret)
	if err == nil {
		t.Fatal("expected an error for a short secret key and malformed fernet key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoes the secret value: %q", err)
	}
}

func TestEnvBool(t *testing.T) {
	cases := []struct {
		val     string
		def     bool
		want    bool
		wantErr bool
	}{
		{"", false, false, false},
		{"", true, true, false},
		{"  ", true, true, false},
		{"true", false, true, false},
		{"TRUE", false, true, false},
		{" 1 ", false, true, false},
		{"yes", false, true, false},
		{"On", false, true, false},
		{"false", true, false, false},
		{"0", true, false, false},
		{"NO", true, false, false},
		{"off", true, false, false},
		{"ture", false, false, true}, // the typo that used to disable strict mode
		{"2", true, false, true},
		{"enabled", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("LM_TEST_BOOL", tc.val)
			got, err := envBool("LM_TEST_BOOL", tc.def)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), `invalid boolean LM_TEST_BOOL="`+tc.val+`"`) {
				t.Errorf("error %q lacks key/value", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// The MCP token is checked on every start, strict or not: the endpoint is
// opt-in and the token alone powers servers on and off.
func TestCheckMCPToken(t *testing.T) {
	cases := []struct {
		name         string
		token        string
		wantErr      bool
		wantMentions []string
	}{
		{name: "unset leaves the feature off", token: ""},
		{name: "openssl rand -hex 32", token: goodSecretKey},
		{name: "base64 with padding", token: "Zm9vYmFyLWJhei1xdXV4LTEyMzQ1Njc4OTAtYWJj/+_~.-=="},
		{name: "exactly the minimum", token: strings.Repeat("a", minSecretKeyLen)},
		{
			name: "one char under the minimum", token: strings.Repeat("a", minSecretKeyLen-1),
			wantErr: true, wantMentions: []string{"LAB_MANAGER_MCP_TOKEN", "31 characters", "at least 32"},
		},
		{
			name: "placeholder", token: "changeme",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_MCP_TOKEN", "openssl rand -hex 32"},
		},
		{
			// A value pasted with its newline can never be sent by a client.
			name: "trailing newline", token: goodSecretKey + "\n",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_MCP_TOKEN", "not a valid bearer token"},
		},
		{name: "inner space", token: goodSecretKey[:32] + " " + goodSecretKey[32:], wantErr: true},
		{name: "quote characters", token: `"` + goodSecretKey + `"`, wantErr: true},
		{name: "padding only", token: strings.Repeat("=", minSecretKeyLen), wantErr: true},
		{name: "padding in the middle", token: goodSecretKey[:32] + "=" + goodSecretKey[32:], wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMCPToken(tc.token)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkMCPToken(%q) error = %v, wantErr %v", tc.token, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), strings.TrimSpace(tc.token)) {
				t.Errorf("error echoes the token: %q", err)
			}
			for _, want := range tc.wantMentions {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q", err, want)
				}
			}
		})
	}
}

// The 32-character floor applies whenever the key is set, not only in strict
// mode; unset is still allowed (a random per-boot key is generated).
func TestCheckSecretKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"unset is allowed", "", false},
		{"openssl rand -hex 32", goodSecretKey, false},
		{"exactly the minimum", strings.Repeat("a", minSecretKeyLen), false},
		{"one under the minimum", strings.Repeat("a", minSecretKeyLen-1), true},
		{"placeholder", "abc123", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSecretKey(tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkSecretKey(%q) error = %v, wantErr %v", tc.key, err, tc.wantErr)
			}
			if err != nil && (!strings.Contains(err.Error(), "LAB_MANAGER_SECRET_KEY") ||
				(tc.key != "" && strings.Contains(err.Error(), tc.key))) {
				t.Errorf("error %q should name the variable and not echo the value", err)
			}
		})
	}
}

// writeSelfSigned writes a throwaway cert/key pair into dir.
func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lab-manager-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestLoadTLSConfig(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSigned(t, dir)
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")

	t.Run("neither set means plain HTTP", func(t *testing.T) {
		cfg, err := loadTLSConfig("", "")
		if err != nil || cfg != nil {
			t.Fatalf("got cfg=%v err=%v, want nil, nil", cfg, err)
		}
	})
	t.Run("both set serves TLS 1.2+", func(t *testing.T) {
		cfg, err := loadTLSConfig(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil || len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("unexpected config %+v", cfg)
		}
	})
	for _, tc := range []struct {
		name, cert, key, want string
	}{
		{"only cert", cert, "", "together"},
		{"only key", "", key, "together"},
		{"missing cert file", missing, key, "LAB_MANAGER_TLS_CERT"},
		{"missing key file", cert, missing, "LAB_MANAGER_TLS_KEY"},
		{"garbage cert", garbage, key, "loading"},
		{"garbage key", cert, garbage, "loading"},
		{"mismatched pair", cert, otherKey(t, dir), "loading"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadTLSConfig(tc.cert, tc.key)
			if err == nil || cfg != nil {
				t.Fatalf("got cfg=%v err=%v, want an error", cfg, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

// otherKey writes a key that does not belong to the cert from writeSelfSigned.
func otherKey(t *testing.T, dir string) string {
	t.Helper()
	sub := filepath.Join(dir, "other")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	_, key := writeSelfSigned(t, sub)
	return key
}
