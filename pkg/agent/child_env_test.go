package agent

// Review of the audit 4 fixes (T-60, R9): "the agent hides its secrets from every program it starts" was not
// true for four of them. This test reads the package's own source, so that the sentence stays true: every
// place that starts a program either goes through collect.Command or sets the program's environment itself
// in the next lines. The two places that are left out run only in the installer's commands, which never read
// env_file.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryProgramTheAgentStartsGetsAnEnvironmentWithoutSecrets(t *testing.T) {
	installerOnly := map[string]string{
		"update.go":       `exec.Command(path, "version")`, // the installer asks the new binary for its version
		"update_linux.go": `exec.Command(p, path)`,         // the installer's restorecon
	}
	files, starts := 0, 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			code, _, _ := strings.Cut(line, "//")
			if !strings.Contains(code, "exec.Command(") && !strings.Contains(code, "exec.CommandContext(") {
				continue
			}
			starts++
			if allowed, ok := installerOnly[filepath.ToSlash(path)]; ok && strings.Contains(code, allowed) {
				continue
			}
			next := strings.Join(lines[i:min(i+5, len(lines))], "\n")
			if !strings.Contains(next, ".Env = ") {
				t.Errorf("%s:%d starts a program without setting its environment (use collect.Command):\n\t%s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Skip("the package's source files are not next to the test program")
	}
	if starts < 5 {
		t.Fatalf("found only %d places that start a program in %d files: the test no longer reads what it should", starts, files)
	}
}
