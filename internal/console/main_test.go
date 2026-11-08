package console

import (
	"os"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

// Fake BMCs listen on 127.0.0.1:<port>, which Server.BMCHost rejects as a
// non-IP. Tests address them verbatim; useRealBMCHost restores the real check.
func TestMain(m *testing.M) {
	bmcHost = func(s *model.Server) (string, bool) { return s.IPAddress, s.IPAddress != "" }
	os.Exit(m.Run())
}

func useRealBMCHost(t *testing.T) {
	t.Helper()
	old := bmcHost
	bmcHost = func(s *model.Server) (string, bool) { return s.BMCHost() }
	t.Cleanup(func() { bmcHost = old })
}
