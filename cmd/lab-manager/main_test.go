package main

import (
	"strings"
	"testing"
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
