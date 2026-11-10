package collect

import (
	"errors"
	"strings"
	"testing"
)

func TestCoreTempCandidates(t *testing.T) {
	// the helper: a service in session 0, somebody signed in at the console in session 1
	got := coreTempCandidates(0, 1, true)
	want := []coreTempName{
		{`Global\CoreTempMappingObjectEx`, true}, {`Global\CoreTempMappingObject`, true},
		{"CoreTempMappingObjectEx", false}, {"CoreTempMappingObject", false},
		{`Session\1\CoreTempMappingObjectEx`, false}, {`Session\1\CoreTempMappingObject`, false},
	}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("name %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// both names keep working: the Global\ names come first, the session names are still tried
	for _, c := range got {
		if c.Global != strings.HasPrefix(c.Name, `Global\`) {
			t.Errorf("%q: Global = %v", c.Name, c.Global)
		}
	}
	// the agent itself in the signed-in user's session (fairy-agent run in a console): no Session\ names
	for _, c := range [][3]uint32{{2, 2, 1}, {0, 0xFFFFFFFF, 1}, {0, 1, 0}} {
		if n := coreTempCandidates(c[0], c[1], c[2] == 1); len(n) != 4 {
			t.Errorf("own %d console %#x known %d: %v", c[0], c[1], c[2], n)
		}
	}
}

// L32: a session name can be created by anyone signed in to that session. It is used only when the object
// belongs to Administrators or SYSTEM.
func TestCoreTempOwnerProblem(t *testing.T) {
	const user = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	global := coreTempName{`Global\CoreTempMappingObjectEx`, true}
	plain := coreTempName{"CoreTempMappingObjectEx", false}
	console := coreTempName{`Session\1\CoreTempMappingObjectEx`, false}
	ok := []struct {
		c     coreTempName
		owner string
		err   error
	}{
		{global, sidAdministrators, nil},
		{global, user, nil},                       // creating a Global\ name needs a privilege ordinary users lack
		{global, "", errors.New("access denied")}, // the owner of a Global\ name is not even asked for
		{plain, sidAdministrators, nil},           // Core Temp started by an administrator (elevated)
		{console, sidAdministrators, nil},         // the same, seen from the helper in session 0
		{console, sidSystem, nil},                 // Core Temp started by a SYSTEM task
		{console, sidTrustedInstaller, nil},
	}
	for _, c := range ok {
		if err := coreTempOwnerProblem(c.c, c.owner, c.err); err != nil {
			t.Errorf("%q owned by %q: refused: %v", c.c.Name, c.owner, err)
		}
	}
	refused := []struct {
		c     coreTempName
		owner string
		err   error
		want  string
	}{
		{console, user, nil, user}, // the signed-in user's own program took the name
		{plain, user, nil, user},
		{console, "S-1-5-32-545", nil, "S-1-5-32-545"},               // Users
		{console, "S-1-5-19", nil, "S-1-5-19"},                       // LocalService
		{console, "", nil, "not to Administrators"},                  // no owner
		{console, "", errors.New("access denied"), "cannot be read"}, // the object does not let its owner be read
		{console, sidAdministrators, errors.New("x"), "cannot be read"},
	}
	for _, c := range refused {
		err := coreTempOwnerProblem(c.c, c.owner, c.err)
		if err == nil || !errors.Is(err, ErrCoreTempUntrusted) || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "global shared memory") {
			t.Errorf("%q owned by %q (%v): %v", c.c.Name, c.owner, c.err, err)
		}
		if errors.Is(err, errCoreTempAbsent) || errors.Is(err, errCoreTempDenied) {
			t.Errorf("%q: reported as absent or denied: %v", c.c.Name, err)
		}
	}
}

func TestCoreTempCopyLen(t *testing.T) {
	for _, c := range []struct {
		region uint64
		n      int
		ok     bool
	}{
		{0, 0, false}, {1, 0, false}, {CoreTempBaseSize - 1, 0, false},
		{CoreTempBaseSize, CoreTempBaseSize, true},
		{4096, 4096, true},              // the original block: one page
		{8192, CoreTempExSize, true},    // the Ex block: two pages, only the block is copied
		{1 << 40, CoreTempExSize, true}, // a huge object under the name: never more than the block
		{^uint64(0), CoreTempExSize, true},
	} {
		n, err := coreTempCopyLen(c.region)
		if n != c.n || (err == nil) != c.ok {
			t.Errorf("region %d: %d %v", c.region, n, err)
		}
	}
}
