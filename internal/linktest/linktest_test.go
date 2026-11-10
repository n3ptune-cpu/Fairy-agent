package linktest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The helper itself: a link to a folder is a link, leads to the folder, and is removed and renamed as the
// link, never as what it points to.
func TestDir(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "inside"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	kind, err := Dir(target, link)
	if err != nil {
		t.Skip("no links to folders here:", err)
	}
	if want := map[bool]string{true: Junction, false: Symlink}[runtime.GOOS == "windows"]; kind != want {
		t.Fatalf("kind %q, want %q", kind, want)
	}
	fi, err := os.Lstat(link)
	if err != nil || !IsLink(fi) || fi.IsDir() || fi.Mode().IsRegular() {
		t.Fatalf("lstat: %v %v", fi, err)
	}
	if b, err := os.ReadFile(filepath.Join(link, "inside")); err != nil || string(b) != "x" {
		t.Fatalf("the link does not lead to the folder: %q %v", b, err)
	}
	// renamed and removed as the link
	moved := filepath.Join(base, "moved")
	if err := os.Rename(link, moved); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(moved); err != nil || !IsLink(fi) {
		t.Fatalf("after the rename: %v %v", fi, err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "inside")); err != nil || string(b) != "x" {
		t.Fatalf("removing the link touched what it pointed to: %q %v", b, err)
	}
	// plain things are not links
	for _, p := range []string{target, filepath.Join(target, "inside")} {
		if fi, _ := os.Lstat(p); IsLink(fi) {
			t.Fatalf("%s counts as a link", p)
		}
	}
	if IsLink(nil) {
		t.Fatal("nil")
	}
}

func TestFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := File(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("a symbolic link to a file needs an elevated window or Developer Mode on Windows:", err)
		}
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); !IsLink(fi) || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("not a symbolic link")
	}
}
