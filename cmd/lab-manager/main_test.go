package main

import (
	"strings"
	"testing"
)

// checkStrictConfig turns a silently-degraded production deploy into a startup
// failure. The cases below are the ones that actually occurred: a
// `docker stack deploy` without the environment exported collapses every
// ${VAR} to "", which disabled KVM auto-login and re-randomised the session
// signing key with nothing but a log line to show for it.
func TestCheckStrictConfig(t *testing.T) {
	cases := []struct {
		name           string
		strict         bool
		secretKey      string
		bmcProxyDomain string
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
			name: "strict deploy with both settings present", strict: true,
			secretKey: "deadbeef", bmcProxyDomain: "pi.home.kilar.net", wantErr: false,
		},
		{
			name: "strict deploy that lost the proxy domain", strict: true,
			secretKey: "deadbeef", bmcProxyDomain: "",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_BMC_PROXY_DOMAIN", "stack deploy"},
		},
		{
			name: "strict deploy that lost the secret key", strict: true,
			secretKey: "", bmcProxyDomain: "pi.home.kilar.net",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_SECRET_KEY"},
		},
		{
			name: "strict deploy that lost the whole environment", strict: true,
			secretKey: "", bmcProxyDomain: "",
			wantErr: true, wantMentions: []string{"LAB_MANAGER_SECRET_KEY", "LAB_MANAGER_BMC_PROXY_DOMAIN"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStrictConfig(tc.strict, tc.secretKey, tc.bmcProxyDomain)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkStrictConfig(%v, %q, %q) error = %v, wantErr %v",
					tc.strict, tc.secretKey, tc.bmcProxyDomain, err, tc.wantErr)
			}
			for _, want := range tc.wantMentions {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should name %q so the fix is obvious", err, want)
				}
			}
		})
	}
}
