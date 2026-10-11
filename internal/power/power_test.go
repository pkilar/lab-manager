package power

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
)

const testFernetKey = "VTfdkyi4hZ3WvGv84jig3XyW_OUl6ovpe1ZU7UUIgRM="

func TestIPMIArgsKeepPasswordOffArgv(t *testing.T) {
	s := &model.Server{IPAddress: "10.0.0.5", IPMIUser: "admin", IPMIPassword: "s3cret-pw"}
	for _, cmd := range [][]string{{"power", "on"}, {"power", "off"}, {"power", "cycle"}, {"power", "status"}} {
		args := ipmiArgs(s, cmd...)
		if !slices.Contains(args, "-E") {
			t.Errorf("%v: argv %v missing -E", cmd, args)
		}
		if slices.Contains(args, "-P") {
			t.Errorf("%v: argv %v must not contain -P", cmd, args)
		}
		if strings.Contains(strings.Join(args, " "), s.IPMIPassword) {
			t.Errorf("%v: argv %v leaks the password", cmd, args)
		}
		if !slices.Equal(args[len(args)-len(cmd):], cmd) {
			t.Errorf("%v: argv %v does not end with the command", cmd, args)
		}
	}
	if !slices.Contains(ipmiEnv(s), "IPMI_PASSWORD=s3cret-pw") {
		t.Error("ipmiEnv must carry IPMI_PASSWORD")
	}
}

func newWoLController(t *testing.T, send func([]byte, string, int) error) (*Controller, *store.Store) {
	t.Helper()
	f, err := secret.NewFernet([]byte(testFernetKey))
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "servers.db"), f)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := NewController(st, true)
	c.sendWoL = send
	return c, st
}

func newWoLServer(t *testing.T, st *store.Store) *model.Server {
	t.Helper()
	s := &model.Server{Name: "wol", IPAddress: "192.168.1.20", MACAddress: "aa:bb:cc:dd:ee:ff", BMCType: model.BMCGeneric, Status: "Off"}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return s
}

func TestWoLAllSendsFailReportsFailure(t *testing.T) {
	boom := errors.New("network is unreachable")
	c, st := newWoLController(t, func([]byte, string, int) error { return boom })
	s := newWoLServer(t, st)

	ok, msg := c.wolCommand(s)
	if ok {
		t.Fatal("wolCommand reported success although every send failed")
	}
	if !strings.Contains(msg, boom.Error()) {
		t.Errorf("message %q does not contain the send error", msg)
	}
	if s.Status != "Off" {
		t.Errorf("in-memory status = %q, want untouched Off", s.Status)
	}
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.Status != "Off" {
		t.Errorf("persisted status = %q, want untouched Off", got.Status)
	}
}

func TestWoLPartialSuccessIsSuccess(t *testing.T) {
	calls := 0
	c, st := newWoLController(t, func(_ []byte, _ string, _ int) error {
		calls++
		if calls == 1 {
			return nil
		}
		return errors.New("later send failed")
	})
	s := newWoLServer(t, st)

	ok, msg := c.wolCommand(s)
	if !ok {
		t.Fatalf("wolCommand = false (%q), want true when one send succeeded", msg)
	}
	if calls != 3 {
		t.Errorf("sends = %d, want 3 (255.255.255.255:9, :7, subnet:9)", calls)
	}
	if s.Status != "On" {
		t.Errorf("status = %q, want On", s.Status)
	}
}

func TestBuildMagicPacket(t *testing.T) {
	p, err := buildMagicPacket("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("buildMagicPacket: %v", err)
	}
	if len(p) != 102 {
		t.Fatalf("len = %d, want 102", len(p))
	}
	if !bytes.Equal(p[:6], bytes.Repeat([]byte{0xFF}, 6)) {
		t.Errorf("header = % x, want 6x FF", p[:6])
	}
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := range 16 {
		if got := p[6+i*6 : 12+i*6]; !bytes.Equal(got, mac) {
			t.Errorf("repetition %d = % x, want % x", i, got, mac)
		}
	}
	// Dash separators are accepted too.
	if _, err := buildMagicPacket("AA-BB-CC-DD-EE-FF"); err != nil {
		t.Errorf("dash-separated MAC: %v", err)
	}
	for _, bad := range []string{"", "not-a-mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00"} {
		if _, err := buildMagicPacket(bad); err == nil {
			t.Errorf("buildMagicPacket(%q) succeeded, want error", bad)
		}
	}
}
