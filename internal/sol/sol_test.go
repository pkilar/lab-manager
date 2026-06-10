package sol

import (
	"slices"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

func TestCredsPrefersIPMIThenRedfish(t *testing.T) {
	cases := []struct {
		name             string
		srv              model.Server
		wantUser, wantPw string
		wantOK           bool
	}{
		{"ipmi preferred", model.Server{IPMIUser: "ipmi", IPMIPassword: "ip", RedfishUser: "rf", RedfishPassword: "rp"}, "ipmi", "ip", true},
		{"redfish fallback", model.Server{RedfishUser: "rf", RedfishPassword: "rp"}, "rf", "rp", true},
		{"none", model.Server{}, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user, pw, ok := Creds(&c.srv)
			if user != c.wantUser || pw != c.wantPw || ok != c.wantOK {
				t.Fatalf("Creds = (%q,%q,%v), want (%q,%q,%v)", user, pw, ok, c.wantUser, c.wantPw, c.wantOK)
			}
		})
	}
}

func TestActivateArgsCarryNoPassword(t *testing.T) {
	args := activateArgs("10.0.0.5", "root")
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "activate"}
	if !slices.Equal(args, want) {
		t.Fatalf("activateArgs = %v, want %v", args, want)
	}
	for _, a := range args {
		if a == "calvin" || a == "secret" {
			t.Fatalf("password leaked into argv: %v", args)
		}
	}
}

func TestDeactivateArgs(t *testing.T) {
	args := deactivateArgs("10.0.0.5", "root")
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "deactivate"}
	if !slices.Equal(args, want) {
		t.Fatalf("deactivateArgs = %v, want %v", args, want)
	}
}
