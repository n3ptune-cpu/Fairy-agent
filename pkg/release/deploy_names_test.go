package release_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// L25 (the code half): the combined polkit file is gone (one rule file per feature). No program text, message
// or comment may still send the owner to it: `fairy-agent setup-self-update` on Linux and the agent's "cannot
// suspend" message did. What they name instead must exist in deploy/ and be what install.sh installs.
func TestNoCodeNamesTheDeletedPolkitFile(t *testing.T) {
	root := filepath.Join("..", "..")
	gone := regexp.MustCompile(`fairy-agent\.polkit\.rules|rules\.d/49-fairy-agent\.rules`)
	sh, err := os.ReadFile(filepath.Join(root, "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if gone.MatchString(line) {
				t.Errorf("%s:%d names the deleted combined polkit file: %s", path, i+1, strings.TrimSpace(line))
			}
			for _, m := range regexp.MustCompile(`deploy/(fairy-agent-[a-z]+\.polkit\.rules)|rules\.d/(49-fairy-agent-[a-z]+\.rules)`).FindAllStringSubmatch(line, -1) {
				named[m[1]+m[2]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fairy-agent-power.polkit.rules", "fairy-agent-update.polkit.rules", "49-fairy-agent-power.rules", "49-fairy-agent-update.rules"} {
		if !named[want] {
			t.Errorf("no program text names %s", want)
		}
	}
	for name := range named {
		if strings.HasPrefix(name, "fairy-agent-") {
			if _, err := os.Stat(filepath.Join(root, "deploy", name)); err != nil {
				t.Errorf("the code names deploy/%s, which does not exist", name)
			}
		}
		if !strings.Contains(string(sh), name) {
			t.Errorf("the code names %s, which install.sh does not install", name)
		}
	}
}
