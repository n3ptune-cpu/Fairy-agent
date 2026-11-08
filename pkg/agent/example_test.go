package agent

import (
	"os"
	"testing"
)

// The shipped example config must load (all optional features off).
func TestExampleConfigParses(t *testing.T) {
	b, err := os.ReadFile("../../deploy/fairy-agent.config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b, "deploy/fairy-agent.config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.ControlEnabled() || c.IPMI.Enabled || !c.ProcessesEnabled() || c.Listen != "" {
		t.Fatalf("%+v", c)
	}
}
