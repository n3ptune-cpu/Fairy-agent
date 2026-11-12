package approval_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// TestSetIntoAFolderThatFailsItsCheck (audit 5, r2-a1-07): a folder that fails its check is "broken" also when
// it holds no trust file, and a set from the network is then refused with 409 already_set like every set on a
// machine that is not "off". The text said "this machine already has a trust file", which was not true. The
// status and the code stay; the text says that there is no file and why none can be written. With a file in
// the folder, usable or not, the text is the old one.
func TestSetIntoAFolderThatFailsItsCheck(t *testing.T) {
	const has, hasNot = "this machine already has a trust file; ", "this machine has no trust file, and none can be set from the network: "
	unsafe := errors.New("C:\\data can be written by BUILTIN\\Users")
	r := newRig(t, false)
	safe := true
	r.files.CheckDir = func(string) error {
		if safe {
			return nil
		}
		return unsafe
	}
	g := r.gate()
	ask := func(what, wantText string) {
		t.Helper()
		in := r.iss.Init()
		for name, ref := range map[string]*approval.Refusal{
			"a set":                   second(g.Init(r.proven(g, r.iss, in))),
			"a set without a proof":   second(g.Init(in)),
			"a challenge for the set": second(g.Challenge(api.TrustSetRequest(in))),
		} {
			if ref == nil || ref.Status != 409 || ref.Code != api.CodeTrustAlreadySet || !strings.HasPrefix(ref.Msg, wantText) {
				t.Errorf("%s, %s: %+v, want 409 already_set %q", what, name, ref, wantText)
			}
		}
	}
	// no file, the folder fails its check
	safe = false
	if st := g.StatusNow(); st.State != api.ApprovalBroken || !strings.Contains(st.Error, "the folder of the trust file is not safe") {
		t.Fatalf("state: %+v", st)
	}
	ask("unsafe folder, no file", hasNot+"the folder of the trust file is not safe: "+unsafe.Error()+". Repair that on the machine, as an administrator; the trust can be set after that (there: fairy-agent helper-trust set)")
	if ents, _ := os.ReadDir(filepath.Dir(r.files.Path)); len(ents) != 0 {
		t.Fatalf("something was written: %v", ents)
	}
	// the folder is repaired: off again, and the set goes through
	safe = true
	if st := g.StatusNow(); st.State != api.ApprovalOff { // (a look every 5 s would find it as well)
		t.Fatalf("state after the repair: %+v", st)
	}
	if st, ref := r.firstSet(g, r.iss, r.iss.Init()); ref != nil || st.State != api.ApprovalRequired {
		t.Fatalf("a set after the repair: %+v %v", st, ref)
	}
	ask("a good trust file", has)
	// a file in a folder that fails its check, and a file that is damaged: there is a file
	safe = false
	g.StatusNow()
	ask("unsafe folder with a file", has)
	safe = true
	must(t, os.WriteFile(r.files.Path, []byte("damaged"), 0o600))
	g.StatusNow()
	ask("a damaged file", has)
}

func second[T any](_ T, ref *approval.Refusal) *approval.Refusal { return ref }

// TestSetWithoutAStateFolder (audit 5, r2-a1-07): without the folder there is no trust file, so the state is
// "off" and requests run. A set from the network cannot be written there; it fails with what is wrong, in
// words, and the state stays what it was. (A standard install always has the folder.)
func TestSetWithoutAStateFolder(t *testing.T) {
	r := newRig(t, false)
	r.files.Path = filepath.Join(filepath.Dir(r.files.Path), "gone", approval.TrustFileName)
	g := r.gate()
	if st := g.Status(); st.State != api.ApprovalOff {
		t.Fatalf("state: %+v", st)
	}
	st, ref := r.firstSet(g, r.iss, r.iss.Init())
	// the reason is held to 200 characters, and the folder's path in it is as long as TMPDIR makes it (audit 6,
	// r4-a1-06: with a TMPDIR of 150 characters the path's end was cut off, and the test looked for all of it)
	why := "the folder of the trust file does not exist: " + filepath.Dir(r.files.Path)
	if len(why) > 200 {
		why = why[:200]
	}
	if ref == nil || ref.Status != 500 || ref.Code != "failed" || !strings.Contains(ref.Msg, "the trust file could not be written: "+why) {
		t.Fatalf("a set without the folder: %+v", ref)
	}
	if st.State != api.ApprovalOff {
		t.Errorf("state afterwards: %+v", st)
	}
	if _, err := os.Lstat(filepath.Dir(r.files.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Error("the folder was made")
	}
}
