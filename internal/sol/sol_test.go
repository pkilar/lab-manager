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
	args := activateArgs("10.0.0.5", "root", model.DefaultSOLInstance)
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
	args := deactivateArgs("10.0.0.5", "root", model.DefaultSOLInstance)
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "deactivate"}
	if !slices.Equal(args, want) {
		t.Fatalf("deactivateArgs = %v, want %v", args, want)
	}
}

// The instance is spelled exactly as ipmitool's usage line documents it —
// `activate [<usesolkeepalive|nokeepalive>] [instance=<number>]` — and instance
// 1 stays implicit so the default argv is unchanged from before the option
// existed.
func TestSOLArgsCarryInstanceOnlyWhenNonDefault(t *testing.T) {
	cases := []struct {
		name     string
		instance int
		want     []string
	}{
		{"default instance stays implicit", 1, []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "activate"}},
		{"COM2", 2, []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "activate", "instance=2"}},
		{"highest instance ipmitool accepts", 15, []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "activate", "instance=15"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := activateArgs("10.0.0.5", "root", c.instance); !slices.Equal(got, c.want) {
				t.Fatalf("activateArgs(instance=%d) = %v, want %v", c.instance, got, c.want)
			}
		})
	}
}

// A teardown that forgot the instance would release payload 1 and strand the
// session the user actually opened — the BMC allows only one at a time, so the
// next launch would fail until the payload timed out.
func TestDeactivateTargetsTheSameInstance(t *testing.T) {
	got := deactivateArgs("10.0.0.5", "root", 2)
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "deactivate", "instance=2"}
	if !slices.Equal(got, want) {
		t.Fatalf("deactivateArgs(instance=2) = %v, want %v", got, want)
	}
}

// Start must carry the server's configured instance into every ipmitool call it
// makes: the pre-activate clear, the console itself, and the cleanup.
func TestStartUsesConfiguredInstanceForEveryCall(t *testing.T) {
	fr := &fakeRunner{}
	m := &Manager{run: fr}
	srv := &model.Server{IPAddress: "10.0.0.5", IPMIUser: "root", IPMIPassword: "calvin", SOLInstance: 2}

	sess, err := m.Start(t.Context(), srv)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.allArgs) != 3 {
		t.Fatalf("expected 3 ipmitool calls (clear, activate, cleanup), got %d: %v", len(fr.allArgs), fr.allArgs)
	}
	for _, args := range fr.allArgs {
		if !slices.Contains(args, "instance=2") {
			t.Errorf("ipmitool call missing instance=2: %v", args)
		}
	}
}

// An unset instance (0, which is what pre-migration rows scan as) must fall
// back to the default rather than emitting `instance=0`, which ipmitool rejects
// outright with "Instance must range from 1 to 15".
func TestStartFallsBackToDefaultInstance(t *testing.T) {
	fr := &fakeRunner{}
	m := &Manager{run: fr}
	srv := &model.Server{IPAddress: "10.0.0.5", IPMIUser: "root", IPMIPassword: "calvin", SOLInstance: 0}

	sess, err := m.Start(t.Context(), srv)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, args := range fr.allArgs {
		for _, a := range args {
			if strings.HasPrefix(a, "instance=") {
				t.Errorf("unset instance should stay implicit, got %q in %v", a, args)
			}
		}
	}
}

// fakeRunner echoes stdin->stdout for `sol activate` (so the test can round-trip
// bytes) and counts `sol deactivate` calls. It records the env it was given.
type fakeRunner struct {
	deactivations atomic.Int32
	mu            sync.Mutex
	lastEnv       []string
	lastArgs      []string
	allArgs       [][]string
}

func (f *fakeRunner) Run(ctx context.Context, args, env []string, stdin io.Reader, stdout io.Writer) error {
	f.mu.Lock()
	f.lastEnv, f.lastArgs = env, args
	f.allArgs = append(f.allArgs, slices.Clone(args))
	f.mu.Unlock()
	// Match the verb by position, not by last element: a non-default instance
	// appends `instance=<n>` after it.
	if slices.Contains(args, "deactivate") {
		f.deactivations.Add(1)
		return nil
	}
	// activate: echo stdin->stdout until stdin closes (Session.Close). The fake
	// ignores ctx; the real execRunner is cancelled via exec.CommandContext.
	if stdin != nil {
		_, _ = io.Copy(stdout, stdin)
	}
	return nil
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
	if !slices.Contains(fr.lastEnv, "IPMI_PASSWORD=calvin") {
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
