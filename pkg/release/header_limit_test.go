package release

import (
	"net/http"
	"testing"
)

// The release client reads at most 64 KiB of response header (net/http's own limit is 10 MiB; the agent that
// asks GitHub runs inside 64 MiB).
func TestReleaseClientLimitsTheResponseHeader(t *testing.T) {
	c, err := NewClient(AgentRepo, "fairy-agent/test")
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok || tr.MaxResponseHeaderBytes != 64<<10 {
		t.Fatal("the release client has no limit on the response header")
	}
}
