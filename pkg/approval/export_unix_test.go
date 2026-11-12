//go:build !windows

package approval

import "testing"

// PretendUser makes UnixCanKeep and UnixKeep believe, for one test, that this process is user uid of group gid,
// and hands every change of a file's owner they would make to lchown instead of the system.
func PretendUser(t testing.TB, uid, gid int, lchown func(path string, uid, gid int) error) {
	e, g, l := keepEuid, keepEgid, keepLchown
	keepEuid, keepEgid, keepLchown = func() int { return uid }, func() int { return gid }, lchown
	t.Cleanup(func() { keepEuid, keepEgid, keepLchown = e, g, l })
}
