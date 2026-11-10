package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// Every option of `join` is in the usage text: --code-stdin (L20) and --pair-v2 (M3) were added to the command
// but not to the text. --config and --state-dir are for tests and unusual installs and stay out of it.
func TestUsageListsEveryJoinOption(t *testing.T) {
	var help bytes.Buffer
	if _, err := parseJoin([]string{"-h"}, &help); err == nil {
		t.Fatal("join -h must not be accepted as a join")
	}
	names := regexp.MustCompile(`(?m)^  -([a-z0-9-]+)`).FindAllStringSubmatch(help.String(), -1)
	if len(names) < 14 {
		t.Fatalf("only %d options found in join's own help:\n%s", len(names), help.String())
	}
	joinUsage := usage[strings.Index(usage, "fairy-agent join"):strings.Index(usage, "fairy-agent pair-status")]
	for _, n := range names {
		if n[1] == "config" || n[1] == "state-dir" {
			continue
		}
		if !strings.Contains(joinUsage, "--"+n[1]) {
			t.Errorf("the usage text of join does not mention --%s", n[1])
		}
	}
	if !strings.Contains(joinUsage, joinCodeEnv) {
		t.Errorf("the usage text of join does not mention %s", joinCodeEnv)
	}
}
