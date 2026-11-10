//go:build windows

package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/internal/linktest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// ownerOf reads a file's owner the plain way (by name), to compare with what the check says.
func ownerOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatal("no owner:", err)
	}
	return owner.String()
}

// H1 on this machine: a config.yaml that someone other than Administrators, SYSTEM or TrustedInstaller owns
// is not edited. A file the tests make in a normal window is exactly that: it belongs to the user who runs
// them. WriteFile must refuse it, say who owns it, and leave it and its folder as they were. (In an elevated
// window new files belong to Administrators, and the same file is edited: there is then nothing to refuse.)
func TestWriteFileRefusesAFileAnotherAccountOwns(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("planted: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	owner := ownerOf(t, p)
	err := WriteFile(p, []byte("a: 2\n"))
	if collect.TrustedOwner(owner) {
		if err != nil {
			t.Fatalf("the file belongs to %s and was refused: %v", owner, err)
		}
		t.Skip("this window is elevated: the files it makes belong to Administrators, so there is no file of another account to refuse")
	}
	if err == nil || !strings.Contains(err.Error(), "is owned by "+owner) || !strings.Contains(err.Error(), "setup-self-update") {
		t.Fatalf("a file owned by %s: %v", owner, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "planted: 1\n" {
		t.Fatalf("the refused file was changed: %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("something was left in the folder: %v", ents)
	}
}

// A link or a folder under the name config.yaml is never edited, whoever owns it. A junction is the link an
// ordinary user can make.
func TestWriteFileRefusesALinkOrAFolder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("a: 2\n")); err == nil {
		t.Fatal("a folder was edited")
	}
	if err := checkOld(p); err == nil || !strings.Contains(err.Error(), "a link or a folder") {
		t.Fatalf("the look at a folder: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if _, err := linktest.Dir(elsewhere, p); err != nil {
		t.Skip("no junction could be made here:", err)
	}
	if err := WriteFile(p, []byte("a: 2\n")); err == nil {
		t.Fatal("a junction was edited")
	}
	if err := checkOld(p); err == nil || !strings.Contains(err.Error(), "a link or a folder") {
		t.Fatalf("the look at a junction: %v", err)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("something was written where the junction points: %v", ents)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("something was left in the folder: %v", ents)
	}
}
