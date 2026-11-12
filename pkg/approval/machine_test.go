package approval_test

// Audit 5, r1-x1-01: an approval is bound to the machine. Every machine with a trust file has a machine id in
// that file; every entry of an approval names the machine it is for; the nonce is made of that too; and the
// machine that checks makes the nonce with its own id.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// machineIDs of two test machines that a panel made up.
const (
	idA = "machine-a-AAAAAAAAAAAAAAAA"
	idB = "machine-b-BBBBBBBBBBBBBBBB"
)

// newRigID is a machine whose trust was set by the panel with the machine id id ("": the machine made one up).
func newRigID(t testing.TB, id string) *rig {
	t.Helper()
	r := newRig(t, false)
	in := r.iss.Init()
	in.MachineID = id
	st, ref := r.firstSet(r.g, r.iss, in)
	if ref != nil || st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil || (id != "" && st.MachineID != id) {
		t.Fatalf("first-time set with machine id %q: %+v, %v", id, st, ref)
	}
	return r
}

func (r *rig) id() string { return r.g.Status().MachineID }

// TestApprovalIsCheckedWithTheMachinesOwnID is the attack of r1-x1-01 at the gate: an approval that was made
// for machine B, carrying a challenge of machine A, is refused by A. Whatever is written into A's entry, A
// makes the nonce with its own id.
func TestApprovalIsCheckedWithTheMachinesOwnID(t *testing.T) {
	a, b := newRigID(t, idA), newRigID(t, idB)
	req := power("shutdown", 60)
	ca, ref := a.g.Challenge(req)
	if ref != nil {
		t.Fatal(ref)
	}
	// what the panel signs when "B" handed it A's challenge: (A's challenge, the request, B's id)
	forB := b.iss.Approve(a.Now(), approvaltest.Entry(idB, ca))
	refused(t, "an approval for B with A's challenge, on A", a.g.Check(req, forB), api.CodeApprovalRefused, approval.ReasonNonce)
	// the attacker rewrites the entry to A's id before he forwards it: the token is still B's
	rewritten := &api.Approval{Token: forB.Token, Entries: []api.MachineEntry{approvaltest.Entry(idA, ca)}}
	refused(t, "the same token with the entry rewritten to A's id", a.g.Check(req, rewritten), api.CodeApprovalRefused, approval.ReasonNonce)
	// no id at all, and an id that is none: the list is refused before the token is looked at
	for name, id := range map[string]string{"no id": "", "a short id": "abc", "an id with a space": "machine a AAAAAAAAAAAAAAAA"} {
		ap := &api.Approval{Token: forB.Token, Entries: []api.MachineEntry{approvaltest.Entry(id, ca)}}
		refused(t, name, a.g.Check(req, ap), api.CodeApprovalRefused, approval.ReasonEntries)
	}
	// the answer is the one every token for another list gets; the machine's own log says what it saw
	if log := a.log.String(); !strings.Contains(log, "names another machine id than this machine's") || strings.Contains(log, forB.Token) {
		t.Errorf("A's log:\n%s", log)
	}
	// none of this used A's challenge up: the approval that was made for A is accepted, once
	forA := a.iss.Approve(a.Now(), approvaltest.Entry(idA, ca))
	accepted(t, "the approval for A, on A", a.g.Check(req, forA))
	refused(t, "and again", a.g.Check(req, forA), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// and B never had that challenge
	refused(t, "the approval for B with A's challenge, on B", b.g.Check(req, forB), api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// The entry as it was sent is not what counts for the machine's own entry: a token that WAS made for A
	// (A's challenge, the request, A's id) is A's, whatever id the list that travelled with it shows.
	ca2, _ := a.g.Challenge(req)
	good := a.iss.Approve(a.Now(), approvaltest.Entry(idA, ca2))
	mislabelled := &api.Approval{Token: good.Token, Entries: []api.MachineEntry{approvaltest.Entry(idB, ca2)}}
	accepted(t, "a token for A whose entry was relabelled on the way", a.g.Check(req, mislabelled))
}

// TestOneApprovalForSeveralMachines: one token covers an entry for each machine (Update all). Each machine
// finds its own entry and checks the whole list as it was signed, with the other machines' ids as sent and its
// own id in its own entry.
func TestOneApprovalForSeveralMachines(t *testing.T) {
	a, b := newRigID(t, idA), newRigID(t, "")
	if a.id() == b.id() {
		t.Fatal("two machines with one id")
	}
	ea, eb := a.entry(update), b.entry(update)
	if ea.MachineID != idA || eb.MachineID != b.id() {
		t.Fatalf("entries %+v %+v", ea, eb)
	}
	both := a.iss.Approve(a.Now(), ea, eb)
	accepted(t, "A", a.g.Check(update, both))
	accepted(t, "B", b.g.Check(update, both))
	// the ids the other way round: neither machine's
	ea, eb = a.entry(update), b.entry(update)
	ea.MachineID, eb.MachineID = eb.MachineID, ea.MachineID
	swapped := a.iss.Approve(a.Now(), ea, eb)
	refused(t, "A, ids swapped", a.g.Check(update, swapped), api.CodeApprovalRefused, approval.ReasonNonce)
	refused(t, "B, ids swapped", b.g.Check(update, swapped), api.CodeApprovalRefused, approval.ReasonNonce)
}

// TestTwoMachinesWithOneMachineID documents what the binding rests on. A machine cannot see other machines. If
// two of them have the same machine id (a disk with a trust file was copied, or somebody set the same id on
// both), an approval for one fits the other again, exactly as before the fix. Telling them apart is the
// panel's part: it keeps each machine's id on record and refuses two machines that show the same one. On the
// machine the repair is `fairy-agent helper-trust set --new-machine-id` (cmd/fairy-agent), which is also what
// `helper-trust show` says.
func TestTwoMachinesWithOneMachineID(t *testing.T) {
	a := newRigID(t, "")
	// the clone: another machine (its own folder, its own gate and open challenges) with a copy of A's trust file
	b := newRig(t, false)
	raw, err := os.ReadFile(a.files.Path)
	must(t, err)
	must(t, os.WriteFile(b.files.Path, raw, 0o600))
	b.g = b.gate()
	if a.id() == "" || a.id() != b.id() {
		t.Fatalf("the clone's id %q, the original's %q", b.id(), a.id())
	}
	req := power("shutdown", 60)
	ca, _ := a.g.Challenge(req)
	// the admin approves "shut down the clone"; the entry carries the id the panel has for the clone, which is
	// also the original's
	forClone := b.iss.Approve(a.Now(), approvaltest.Entry(b.id(), ca))
	if ref := a.g.Check(req, forClone); ref != nil {
		t.Fatalf("with one id on two machines the approval for one is expected to fit the other (that is what this test documents); it was refused: %v", ref)
	}
	// nothing on either machine notices: no word of it in the logs
	for _, log := range []string{a.log.String(), b.log.String()} {
		if strings.Contains(log, "another machine") || strings.Contains(log, "same id") {
			t.Errorf("a machine claims to have noticed:\n%s", log)
		}
	}
}

// TestMachineIDIsSetWithTheFirstTrust: the panel's id when it sends one, an id of the machine's own when it
// does not; in the trust file, in the approval block, and the same after a restart.
func TestMachineIDIsSetWithTheFirstTrust(t *testing.T) {
	chosen := newRigID(t, idA)
	if got := chosen.gate().Status().MachineID; got != idA {
		t.Errorf("after a restart: %q", got)
	}
	if st, tr, _, err := chosen.files.Load(); st != api.ApprovalRequired || err != nil || tr.MachineID != idA {
		t.Errorf("the file: %s %v %+v", st, err, tr)
	}
	if !strings.Contains(chosen.log.String(), "machine_id="+idA) {
		t.Errorf("the log of the first-time set does not name the id:\n%s", chosen.log.String())
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		r := newRigID(t, "")
		id := r.id()
		b, err := base64.RawURLEncoding.Strict().DecodeString(id)
		if err != nil || len(b) != 16 || len(id) != 22 {
			t.Fatalf("a made-up id is not 16 bytes in base64url: %q", id)
		}
		if seen[id] {
			t.Fatalf("the same id twice: %q", id)
		}
		seen[id] = true
		if got := r.gate().Status().MachineID; got != id {
			t.Errorf("after a restart: %q, was %q", got, id)
		}
	}
	// the id comes from the gate's source of random numbers, and without one nothing is written
	r := newRig(t, false)
	g := approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, Rand: bytes.NewReader(bytes.Repeat([]byte{0xAB}, 32+16))})
	in := r.iss.Init()
	in.MachineID = ""
	if st, ref := r.firstSet(g, r.iss, in); ref != nil || st.MachineID != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 16)) {
		t.Fatalf("with a known source: %+v, %v", st, ref)
	}
	r = newRig(t, false)
	g = approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 32+15))})
	if st, ref := r.firstSet(g, r.iss, in); ref == nil || ref.Status != 500 || st.State != api.ApprovalOff {
		t.Fatalf("without random numbers for the id: %+v, %v", st, ref)
	}
	if _, err := os.Lstat(r.files.Path); err == nil {
		t.Fatal("a trust file was written without a machine id of its own")
	}
	if id, err := approval.NewMachineID(nil); err != nil || api.CheckMachineID(id) != nil {
		t.Errorf("NewMachineID: %q, %v", id, err)
	}
}

// TestCallerChosenMachineIDIsChecked: the id the panel proposes is taken only if it is one; anything else is
// refused before the proof is looked at, and nothing is written.
func TestCallerChosenMachineIDIsChecked(t *testing.T) {
	for name, id := range map[string]string{
		"too short":       strings.Repeat("a", api.MinMachineID-1),
		"one character":   "a",
		"too long":        strings.Repeat("a", api.MaxMachineID+1),
		"far too long":    strings.Repeat("a", 5000),
		"a space":         "machine a AAAAAAAAAAAAAAAA",
		"a newline":       "machine-a-AAAAAAAAAAAAAAA\n",
		"a slash":         "machine/a/AAAAAAAAAAAAAAAA",
		"padding":         "machine-a-AAAAAAAAAAAAAAA=",
		"a plus":          "machine+a+AAAAAAAAAAAAAAAA",
		"a quote":         `machine"a"AAAAAAAAAAAAAAAA`,
		"a NUL":           "machine-a-AAAAAAAAAAAAAA\x00A",
		"not ASCII":       "maschine-ä-AAAAAAAAAAAAAAA",
		"spaces only":     strings.Repeat(" ", 30),
		"a path":          "../../../../etc/passwd-AAAA",
		"an escape":       "machine-a-AAAAAAAAAAAAA\x1b[2J",
		"a control token": "a.b.c.dddddddddddddddddddd",
	} {
		r := newRig(t, false)
		in := r.iss.Init()
		in.MachineID = id
		// the proof is built the way an honest panel would, where the id lets it (the nonce refuses such an id too)
		c, ref := r.g.Challenge(api.TrustSetRequest(in))
		if ref != nil {
			t.Fatal(ref)
		}
		in.Approval = &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{approvaltest.Entry(id, c)}}
		st, ref := r.g.Init(in)
		if ref == nil || ref.Status != 400 || ref.Code != api.CodeTrustInvalid || !strings.Contains(ref.Msg, "machine_id") || st.State != api.ApprovalOff {
			t.Errorf("%s: %+v, %v", name, st, ref)
		}
		if _, err := os.Lstat(r.files.Path); err == nil {
			t.Errorf("%s: a trust file was written", name)
		}
	}
	// "" is "none proposed": the machine makes one up, and never stores an empty one
	r := newRigID(t, "")
	if raw, _ := os.ReadFile(r.files.Path); !bytes.Contains(raw, []byte(`"machine_id": "`+r.id()+`"`)) || bytes.Contains(raw, []byte(`"machine_id": ""`)) {
		t.Errorf("the file:\n%s", raw)
	}
	// the longest and the shortest id that are one
	for _, id := range []string{strings.Repeat("a", api.MinMachineID), strings.Repeat("Z", api.MaxMachineID), "00112233445566778899aabbccddeeff"} {
		newRigID(t, id)
	}
}

// TestProofIsBoundToTheMachineID: the proof of a first-time set is an approval whose entry carries the proposed
// machine id, exactly as it is sent. A proof for one id sets no other id, a proof without one sets none that is
// sent with it, and the other way round.
func TestProofIsBoundToTheMachineID(t *testing.T) {
	for name, c := range map[string]struct {
		proven, sent string // the id in the entry the token was made for, and the machine_id of the body
		ok           bool
	}{
		"the same id":                            {idA, idA, true},
		"none in both: the machine picks":        {"", "", true},
		"proven for one id, another sent":        {idA, idB, false},
		"proven for an id, none sent":            {idA, "", false},
		"proven without an id, one sent":         {"", idA, false},
		"proven for an id, the same and a tail":  {idA, idA + "A", false},
		"proven for an id, the same in capitals": {idA, strings.ToUpper(idA), false},
	} {
		r := newRig(t, false)
		in := r.iss.Init()
		in.MachineID = c.sent
		ch, ref := r.g.Challenge(api.TrustSetRequest(in)) // the hash has no machine id in it: the same challenge for every id
		if ref != nil {
			t.Fatal(ref)
		}
		// honest: the entry as it was signed. And the attacker's version: the entry relabelled to what is sent.
		for how, wire := range map[string]string{"entry as signed": c.proven, "entry relabelled": c.sent} {
			token := r.iss.Approve(r.Now(), approvaltest.Entry(c.proven, ch)).Token
			in.Approval = &api.Approval{Token: token, Entries: []api.MachineEntry{approvaltest.Entry(wire, ch)}}
			st, ref := r.g.Init(in)
			switch {
			case c.ok && (ref != nil || st.State != api.ApprovalRequired || (c.sent != "" && st.MachineID != c.sent) || api.CheckMachineID(st.MachineID) != nil):
				t.Errorf("%s, %s: %+v, %v", name, how, st, ref)
			case !c.ok && (ref == nil || ref.Code != api.CodeTrustProofRefused || !strings.HasPrefix(ref.Msg, "proof refused ("+approval.ReasonNonce+")") || st.State != api.ApprovalOff):
				t.Errorf("%s, %s: %+v, %v", name, how, st, ref)
			}
			if c.ok {
				break // the trust is set; the second form would be already_set
			}
			if _, err := os.Lstat(r.files.Path); err == nil {
				t.Errorf("%s, %s: a trust file was written", name, how)
			}
		}
	}
}

// TestMachineIDStaysWhileTheTrustIsLocked: once a trust file is there, no request from the network changes the
// machine id: a set with another id, with or without a proof, is answered already_set like every other set,
// and so is the challenge for one.
func TestMachineIDStaysWhileTheTrustIsLocked(t *testing.T) {
	r := newRigID(t, idA)
	before, err := os.ReadFile(r.files.Path)
	must(t, err)
	in := r.iss.Init()
	for _, id := range []string{idB, idA, "", "not an id"} {
		in.MachineID = id
		if _, ref := r.g.Challenge(api.TrustSetRequest(in)); ref == nil || ref.Code != api.CodeTrustAlreadySet {
			t.Errorf("challenge for a set with the id %q: %v", id, ref)
		}
		in.Approval = r.iss.Approve(r.Now(), api.MachineEntry{MachineID: idB, Challenge: strings.Repeat("A", 43), Request: "trust_set hash=" + api.TrustHash(in)})
		if st, ref := r.g.Init(in); ref == nil || ref.Status != 409 || ref.Code != api.CodeTrustAlreadySet || st.MachineID != idA {
			t.Errorf("a set with the id %q on a locked machine: %+v, %v", id, st, ref)
		}
	}
	if after, _ := os.ReadFile(r.files.Path); !bytes.Equal(before, after) || r.id() != idA {
		t.Error("the trust file changed")
	}
	// a broken trust file locks as well
	must(t, os.WriteFile(r.files.Path, []byte("{"), 0o600))
	g := r.gate()
	in.MachineID = idB
	if st, ref := g.Init(in); ref == nil || ref.Code != api.CodeTrustAlreadySet || st.State != api.ApprovalBroken || st.MachineID != "" {
		t.Errorf("a set on a machine with a broken trust file: %+v, %v", st, ref)
	}
}

// legacyFile is a trust file as the test build of 2026-11-11 wrote it: everything but the machine id.
func legacyFile(t testing.TB) []byte {
	t.Helper()
	tr, err := approval.FromInit(approvaltest.New().Init(approvaltest.User, "u2"), nowForTests, nil)
	must2(t, err)
	tr.MachineID = ""
	raw := tr.Marshal()
	if bytes.Contains(raw, []byte("machine_id")) || !bytes.HasPrefix(raw, []byte("{\n  \"version\": 1,\n  \"issuer\": ")) {
		t.Fatalf("not the old file:\n%s", raw)
	}
	return raw
}

func must2(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func tempFiles(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	list, err := os.ReadDir(dir)
	must2(t, err)
	for _, e := range list {
		if e.Name() != approval.TrustFileName {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestTrustFileWithoutMachineIDGetsOne: a trust file from before machine ids gets an id from the gate that owns
// the file, at its first look (the service's start): once, that one member and not a byte besides, the same id
// at every later start.
func TestTrustFileWithoutMachineIDGetsOne(t *testing.T) {
	for name, old := range map[string][]byte{
		"as the test build wrote it": legacyFile(t),
		"written by hand, compact":   bytes.ReplaceAll(bytes.ReplaceAll(legacyFile(t), []byte("\n"), nil), []byte("  "), nil),
		"written by hand, odd":       append([]byte("\n\t  "), bytes.ReplaceAll(legacyFile(t), []byte("\n  \"issuer\""), []byte("\n\n\n      \"issuer\""))...),
	} {
		r := newRig(t, false)
		must(t, os.WriteFile(r.files.Path, old, 0o600))
		// nothing is ever checked with the file as it is
		if st, tr, _, err := r.files.Load(); st != api.ApprovalBroken || !errors.Is(err, approval.ErrNoMachineID) || tr == nil || tr.MachineID != "" {
			t.Fatalf("%s: Load of the old file: %s %v", name, st, err)
		}
		if _, err := approval.ParseTrust(old); !errors.Is(err, approval.ErrNoMachineID) {
			t.Fatalf("%s: ParseTrust of the old file: %v", name, err)
		}
		g := r.gate()
		st := g.Status()
		if st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil || st.Users != 2 || st.SetBy != "panel" || st.TrustHash != api.TrustHash(approvaltest.New().Init(approvaltest.User, "u2")) {
			t.Fatalf("%s: after the start: %+v", name, st)
		}
		now, err := os.ReadFile(r.files.Path)
		must(t, err)
		at := bytes.IndexByte(old, '{') + 1
		want := string(old[:at]) + "\n  \"machine_id\": \"" + st.MachineID + "\"," + string(old[at:])
		if string(now) != want {
			t.Errorf("%s: more than the one member changed:\n%s\nwant\n%s", name, now, want)
		}
		if left := tempFiles(t, filepath.Dir(r.files.Path)); len(left) != 0 {
			t.Errorf("%s: files left behind: %v", name, left)
		}
		if n := strings.Count(r.log.String(), "one was added"); n != 1 || !strings.Contains(r.log.String(), "machine_id="+st.MachineID) {
			t.Errorf("%s: the log says it %d times:\n%s", name, n, r.log.String())
		}
		// later starts, and the same gate at its later looks: the same id, the file untouched, nothing logged again
		for i := 0; i < 3; i++ {
			if got := r.gate().StatusNow().MachineID; got != st.MachineID {
				t.Errorf("%s: start %d: id %q, was %q", name, i, got, st.MachineID)
			}
		}
		r.wait(6 * 1e9)
		if got := g.Status().MachineID; got != st.MachineID {
			t.Errorf("%s: at a later look: id %q", name, got)
		}
		if again, _ := os.ReadFile(r.files.Path); !bytes.Equal(again, now) || strings.Count(r.log.String(), "one was added") != 1 {
			t.Errorf("%s: the file was written again", name)
		}
		// and it works: an approval with the new id is accepted, one without an id or with another is not
		req := power("reboot", 60)
		accepted(t, name+": an approval with the added id", g.Check(req, r.iss.Approve(r.Now(), r.entryFrom(g, req))))
		e := r.entryFrom(g, req)
		e.MachineID = idB
		refused(t, name+": an approval with another id", g.Check(req, r.iss.Approve(r.Now(), e)), api.CodeApprovalRefused, approval.ReasonNonce)
	}
}

// TestGateThatOnlyReadsAddsNoMachineID: the Windows agent's gate reads the helper's trust file and never
// writes it. A file without a machine id is broken for it (everything that needs an approval is refused) until
// the owner has added the id; then it reads the owner's id.
func TestGateThatOnlyReadsAddsNoMachineID(t *testing.T) {
	r := newRig(t, false)
	old := legacyFile(t)
	must(t, os.WriteFile(r.files.Path, old, 0o600))
	reader := approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, ReadOnly: true})
	st := reader.Status()
	if st.State != api.ApprovalBroken || st.MachineID != "" || st.Issuer != "" || !strings.Contains(st.Error, "has no machine_id") || !strings.Contains(st.Error, "this version of fairy-agent-helper on Windows") {
		t.Fatalf("the reading gate: %+v", st)
	}
	if now, _ := os.ReadFile(r.files.Path); !bytes.Equal(now, old) || len(tempFiles(t, filepath.Dir(r.files.Path))) != 0 {
		t.Fatal("the reading gate wrote")
	}
	req := power("shutdown", 60)
	for what, ref := range map[string]*approval.Refusal{
		"a request without approval": reader.Precheck(req, false),
		"a request with one":         reader.Check(req, &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: idA, Challenge: strings.Repeat("A", 43), Request: "power action=shutdown delay_s=60"}}}),
	} {
		if ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable || !strings.Contains(ref.Msg, "machine_id") {
			t.Errorf("%s: %v", what, ref)
		}
	}
	if _, ref := reader.Challenge(req); ref == nil || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("a challenge: %v", ref)
	}
	if _, ref := reader.Init(r.iss.Init()); ref == nil || ref.Code != api.CodeTrustAlreadySet {
		t.Errorf("a first-time set: %v", ref)
	}
	// the owner starts: it adds the id; the reader sees it at its next look
	owner := r.gate()
	id := owner.Status().MachineID
	if api.CheckMachineID(id) != nil {
		t.Fatalf("the owner: %+v", owner.Status())
	}
	if got := reader.StatusNow(); got.State != api.ApprovalRequired || got.MachineID != id {
		t.Errorf("the reader after the owner's start: %+v", got)
	}
}

// TestMachineIDThatCannotBeAddedFailsClosed: when the id cannot be added, the file stays as it was and the state
// is broken, with the reason in plain words: nothing is approved and nothing runs unapproved. When what was in
// the way is gone, the id is added at the next look.
func TestMachineIDThatCannotBeAddedFailsClosed(t *testing.T) {
	r := newRig(t, false)
	old := legacyFile(t)
	must(t, os.WriteFile(r.files.Path, old, 0o600))
	blocked := true
	files := r.files
	files.Keep = func(string, os.FileInfo) error {
		if blocked {
			return errors.New("the file belongs to root and cannot be given back to root")
		}
		return nil
	}
	g := approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent, Now: r.Now})
	st := g.Status()
	if st.State != api.ApprovalBroken || st.MachineID != "" || !strings.Contains(st.Error, "has no machine_id, and adding one failed: the file belongs to root and cannot be given back to root") ||
		!strings.Contains(st.Error, "fairy-agent helper-trust set") {
		t.Fatalf("state: %+v", st)
	}
	if now, _ := os.ReadFile(r.files.Path); !bytes.Equal(now, old) {
		t.Fatal("the file changed although the id could not be added")
	}
	if left := tempFiles(t, filepath.Dir(r.files.Path)); len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
	req := power("shutdown", 60)
	if ref := g.Precheck(req, false); ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("a request without approval while the id is missing: %v", ref)
	}
	if ref := g.Check(fanMode("full"), nil); ref == nil || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("a fan request while the id is missing: %v", ref)
	}
	blocked = false
	r.wait(6 * 1e9) // the next look
	if st := g.Status(); st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil {
		t.Fatalf("after the obstacle is gone: %+v", st)
	}

	// a file that somebody else replaces while the id is being added is not overwritten
	r2 := newRig(t, false)
	must(t, os.WriteFile(r2.files.Path, old, 0o600))
	admins, err := approval.NewTrust(approval.Trust{MachineID: idB, Issuer: "https://admin.test.invalid", ClientID: "admin", Keys: r.iss.Init().Keys, Users: []string{"root"}})
	must(t, err)
	racing := r2.files
	racing.Keep = func(string, os.FileInfo) error { return r2.files.Replace(admins) } // helper-trust set, at the worst moment
	if id, err := racing.AddMachineID(nil); err == nil || !strings.Contains(err.Error(), "changed in the meantime") {
		t.Fatalf("AddMachineID over a file that was replaced: %q, %v", id, err)
	}
	if _, tr, _, _ := r2.files.Load(); tr == nil || tr.ClientID != "admin" || tr.MachineID != idB {
		t.Fatalf("the administrator's file was overwritten: %+v", tr)
	}
	if left := tempFiles(t, filepath.Dir(r2.files.Path)); len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
	// AddMachineID is for exactly one kind of file
	if _, err := r2.files.AddMachineID(nil); err == nil || !strings.Contains(err.Error(), "has a machine id already") {
		t.Errorf("AddMachineID on a file with an id: %v", err)
	}
	none := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	if _, err := none.AddMachineID(nil); err == nil {
		t.Error("AddMachineID without a file")
	}
}

// TestBrokenTrustFileGetsNoMachineID: a file that is broken for any other reason stays broken and is never
// rewritten; in particular a file whose machine id is there and is not one is not "repaired".
func TestBrokenTrustFileGetsNoMachineID(t *testing.T) {
	good := legacyFile(t)
	withID := func(id string) []byte {
		return bytes.Replace(good, []byte("{\n"), []byte("{\n  \"machine_id\": \""+id+"\",\n"), 1)
	}
	for name, raw := range map[string][]byte{
		"not JSON":                      []byte("{"),
		"empty":                         {},
		"an unknown member":             bytes.Replace(good, []byte("{\n"), []byte("{\n  \"machine\": \"x\",\n"), 1),
		"another version":               bytes.Replace(good, []byte(`"version": 1`), []byte(`"version": 2`), 1),
		"an http issuer":                bytes.Replace(good, []byte("https://"), []byte("http://"), 1),
		"machine id too short":          withID("abc"),
		"machine id empty but there":    append([]byte(nil), bytes.Replace(withID("X"), []byte(`"X"`), []byte(`" "`), 1)...),
		"machine id with a space":       withID("machine a AAAAAAAAAAAAAAAA"),
		"machine id too long":           withID(strings.Repeat("a", api.MaxMachineID+1)),
		"machine id twice":              bytes.Replace(withID(idA), []byte("{\n"), []byte("{\n  \"machine_id\": \""+idB+"\",\n"), 1),
		"machine id a number":           bytes.Replace(good, []byte("{\n"), []byte("{\n  \"machine_id\": 12345678901234567890123,\n"), 1),
		"two objects":                   append(append([]byte(nil), good...), good...),
		"larger than a trust file may":  append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), 70<<10)...),
		"good, then something after it": append(append([]byte(nil), good...), []byte("x")...),
	} {
		r := newRig(t, false)
		must(t, os.WriteFile(r.files.Path, raw, 0o600))
		g := r.gate()
		st := g.Status()
		if st.State != api.ApprovalBroken || st.MachineID != "" {
			t.Errorf("%s: %+v", name, st)
		}
		if now, _ := os.ReadFile(r.files.Path); !bytes.Equal(now, raw) || len(tempFiles(t, filepath.Dir(r.files.Path))) != 0 {
			t.Errorf("%s: the file was rewritten", name)
		}
		if strings.Contains(r.log.String(), "one was added") {
			t.Errorf("%s: the log claims an id was added", name)
		}
		if ref := g.Precheck(power("shutdown", 60), false); ref == nil || ref.Code != api.CodeApprovalUnavailable {
			t.Errorf("%s: a request: %v", name, ref)
		}
		if _, err := r.files.AddMachineID(nil); err == nil {
			t.Errorf("%s: AddMachineID took it", name)
		}
	}
}

// TestFailingMachineIDIsLoggedOnce (second review of 8119ea0..ae9384f, N3): an id that cannot be added is
// tried again at every look, and each try has a temporary file with another made-up name. The system's error
// carries that name, so the reason was another text at every look, and the gate, which writes a state into the
// log once for as long as its reason stays the same, wrote "approval: broken" every five seconds while a panel
// asked. The name is out of the text: one line, and a reason that reads the same every time.
func TestFailingMachineIDIsLoggedOnce(t *testing.T) {
	r := newRig(t, false)
	dir, err := os.MkdirTemp("", "tn") // a short path: the whole reason fits into the answer's 300 characters
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	r.files.Path = filepath.Join(dir, approval.TrustFileName)
	must(t, os.WriteFile(r.files.Path, legacyFile(t), 0o600))
	files := r.files
	var names []string
	files.Keep = func(tmp string, _ os.FileInfo) error {
		names = append(names, filepath.Base(tmp))
		return &os.PathError{Op: "lchown", Path: tmp, Err: errors.New("invalid argument")} // as the system says it
	}
	g := approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	var first string
	for look := 0; look < 5; look++ {
		st := g.Status()
		if st.State != api.ApprovalBroken || !strings.Contains(st.Error, "adding one failed: lchown ") || !strings.Contains(st.Error, "/.approval-trust-*.tmp: invalid argument") {
			t.Fatalf("look %d: %+v", look+1, st)
		}
		if look == 0 {
			first = st.Error
		} else if st.Error != first {
			t.Errorf("look %d: the reason changed:\n%s\n%s", look+1, first, st.Error)
		}
		r.wait(6 * time.Second)
	}
	if len(names) != 5 || names[0] == names[1] || names[1] == names[2] {
		t.Fatalf("the test did not see five tries with names of their own: %v", names)
	}
	for _, n := range names {
		if strings.Contains(first, n) || strings.Contains(r.log.String(), n) {
			t.Errorf("the name of a temporary file (%s) is in the reason or in the log", n)
		}
	}
	if n := strings.Count(r.log.String(), `msg="approval: broken"`); n != 1 {
		t.Errorf("%d lines \"approval: broken\" for five looks at the same failure, want 1:\n%s", n, r.log.String())
	}
	if left := tempFiles(t, filepath.Dir(r.files.Path)); len(left) != 0 {
		t.Errorf("files left behind: %v", left)
	}
}
