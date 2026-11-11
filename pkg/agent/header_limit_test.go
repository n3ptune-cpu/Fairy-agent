package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// The agent's own HTTP clients have a limit on the response header too (net/http's is 10 MiB when none is set,
// and the agent runs inside 64 MiB): the client for a BMC's Redfish API, and the update's health check.
func TestAgentClientsLimitTheResponseHeader(t *testing.T) {
	b := NewBMCRelay(BMCRelayConfig{}, "")
	c, _ := b.client(strings.Repeat("ab", 32))
	if tr, ok := c.Transport.(*http.Transport); !ok || tr.MaxResponseHeaderBytes != devices.MaxResponseHeaderBytes {
		t.Fatal("the BMC relay's client has no limit on the response header")
	}
	// whatever holds the agent's port answers the health check with a megabyte of header: refused
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 1024; i++ {
			w.Header().Add("X-Fill", strings.Repeat("a", 1000))
		}
		_, _ = w.Write([]byte(`{"proof":"x"}`))
	}))
	defer srv.Close()
	// No limit on the time here: the check first derives its key (600,000 rounds), which alone takes two
	// seconds on a loaded machine under the race detector. How fast an oversized header is refused, and with
	// how little memory, is measured in pkg/devices on the same transport setting.
	err := CheckRunning(context.Background(), healthCfg(t, srv.URL), "42-bbbbbbb")
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatal("an answer with 1 MiB of header passed the health check's client:", err)
	}
}
