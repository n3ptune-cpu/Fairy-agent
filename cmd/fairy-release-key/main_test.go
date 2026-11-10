package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// L26 (the code half): the message of `fairy-release-key gen` told the owner to store the private key as a
// repository secret, where every workflow run can read it. The release workflow reads it from the GitHub
// Environment "release", which waits for the required reviewer; the message now says that, and says not to
// make a repository secret.
func TestGenTellsTheOwnerToUseTheReleaseEnvironment(t *testing.T) {
	msg := genMessage("/home/me/fairy-release-key.txt", "release/signing.pub")
	for _, want := range []string{`GitHub Environment "release"`, "Settings > Environments > release", "Add environment secret",
		"FAIRY_RELEASE_KEY", "BOTH", "Do NOT add it as a repository secret", "/home/me/fairy-release-key.txt", "release/signing.pub"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "New repository secret") {
		t.Errorf("the message still sends the owner to \"New repository secret\":\n%s", msg)
	}
	// and it matches what the workflow does: the job that signs runs in that environment
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*environment:\s*release\b`).Match(wf) {
		t.Error("release.yml has no job with `environment: release`")
	}
}
