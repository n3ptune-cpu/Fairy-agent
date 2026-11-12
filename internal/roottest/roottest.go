// Package roottest answers one question for the tests that act as root: can this process give a file to
// another user?
//
// Real root can. Root inside a user namespace that maps a single user (`unshare -r`, many CI sandboxes and
// containers) cannot: every other user id does not exist there, and chown to it fails with "invalid argument".
// A test that plays root handing files to the agent's account, or an attacker who owns a folder, cannot run
// there, and says so instead of failing.
package roottest

import (
	"os"
	"path/filepath"
	"testing"
)

// probeID is a user and group that the test process is not.
const probeID = 54321

// CanChown reports whether this process can give a file to another user and group. The error is the system's
// when it cannot.
func CanChown(t testing.TB) (bool, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(f, probeID, probeID); err != nil {
		return false, err
	}
	return true, nil
}

// NeedOtherUsers skips the test when this process is root in name only: it runs as user 0 and still cannot give
// a file to another user. A process that is not root at all is not skipped here (its test decides for itself).
func NeedOtherUsers(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	if ok, err := CanChown(t); !ok {
		t.Skipf("skipped: this test gives files to other users, which this root cannot do (%v). That is root inside a user namespace with a single user (unshare -r, a sandbox); run the tests as real root, or as an ordinary user, to have it run", err)
	}
}
