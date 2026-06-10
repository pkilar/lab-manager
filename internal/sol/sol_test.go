package sol

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// fakeRunner echoes stdin->stdout for `sol activate` (so the test can round-trip
// bytes) and counts `sol deactivate` calls. It records the env it was given.
type fakeRunner struct {
	deactivations atomic.Int32
	mu            sync.Mutex
	lastEnv       []string
	lastArgs      []string
}

func (f *fakeRunner) Run(ctx context.Context, args, env []string, stdin io.Reader, stdout io.Writer) error {
	f.mu.Lock()
	f.lastEnv, f.lastArgs = env, args
	f.mu.Unlock()
	if len(args) > 0 && args[len(args)-1] == "deactivate" {
		f.deactivations.Add(1)
		return nil
	}
	if stdin != nil { // activate: echo until stdin closes (Session.Close) or ctx done
		_, _ = io.Copy(stdout, stdin)
	}
	return nil
}

func envHas(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func TestSessionBridgesIOAndDeactivatesOnClose(t *testing.T) {
	fr := &fakeRunner{}
	m := &Manager{run: fr}
	srv := &model.Server{IPAddress: "10.0.0.5", RedfishUser: "root", RedfishPassword: "calvin"}

	sess, err := m.Start(t.Context(), srv)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if _, err := io.WriteString(sess.Stdin, "uname -a\n"); err != nil {
		t.Fatalf("write keystrokes: %v", err)
	}
	got := make([]byte, len("uname -a\n"))
	if _, err := io.ReadFull(sess.Output, got); err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "uname -a\n" {
		t.Fatalf("bridge round-trip = %q, want %q", got, "uname -a\n")
	}

	// A `sol deactivate` must run specifically on Close (releasing the BMC
	// payload), beyond the best-effort pre-activate clear.
	before := fr.deactivations.Load()
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sess.Close() != nil { // idempotent
		t.Fatal("second Close should be a no-op")
	}
	if fr.deactivations.Load() <= before {
		t.Fatal("expected sol deactivate to run on Close")
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()
	if !envHas(fr.lastEnv, "IPMI_PASSWORD=calvin") {
		t.Fatal("IPMI_PASSWORD not passed in env")
	}
	if strings.Contains(strings.Join(fr.lastArgs, " "), "calvin") {
		t.Fatalf("password leaked into argv: %v", fr.lastArgs)
	}
}

func TestStartFailsWithoutCreds(t *testing.T) {
	m := &Manager{run: &fakeRunner{}}
	if _, err := m.Start(t.Context(), &model.Server{IPAddress: "10.0.0.5"}); err == nil {
		t.Fatal("expected error when no credentials are configured")
	}
}
