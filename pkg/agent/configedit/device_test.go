package configedit

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

func TestAddDevice(t *testing.T) {
	item := []KV{{"id", "local-ups"}, {"type", "nut"}, {"host", "127.0.0.1"}, {"ups", []string{"cyberpower"}}}
	example, err := os.ReadFile("../../../deploy/fairy-agent.config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"example":   string(example),
		"empty":     "",
		"missing":   "processes:\n  enabled: true\n",
		"null":      "ups:\nwol: {enabled: false}\n",
		"flowEmpty": "ups: []   # none yet\r\nwol:\r\n  enabled: false\r\n",
	} {
		out, err := AddDevice([]byte(in), "ups", item)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cfg, err := agent.Parse(out, "/x/config.yaml")
		if err != nil {
			t.Fatalf("%s: result does not parse: %v\n%s", name, err, out)
		}
		if len(cfg.UPS) != 1 || cfg.UPS[0]["host"] != "127.0.0.1" || cfg.UPS[0]["id"] != "local-ups" {
			t.Fatalf("%s: ups = %v", name, cfg.UPS)
		}
		if name == "example" && !strings.Contains(string(out), "# - {id: local, host: 127.0.0.1") {
			t.Fatalf("comments lost:\n%s", out)
		}
		if name == "flowEmpty" && !strings.Contains(string(out), "# none yet\r\n") {
			t.Fatalf("comment / line ending lost: %q", out)
		}
	}
	_, err = AddDevice([]byte("ups:\n  - {id: a, host: 10.0.0.1}\n"), "ups", item)
	if !errors.Is(err, ErrListNotEmpty) {
		t.Fatalf("non-empty list: %v", err)
	}
}
