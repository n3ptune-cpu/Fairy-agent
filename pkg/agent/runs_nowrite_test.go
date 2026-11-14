package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// lockInTheWay makes every write of the run record fail while the record itself can still be read: the name
// of the writers' lock is taken by a folder. The returned function puts things right again.
func lockInTheWay(t *testing.T, r *rrig) (free func()) {
	t.Helper()
	lock := filepath.Join(filepath.Dir(r.files.Path), approval.RunLockName)
	if err := os.Remove(lock); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(lock); err != nil {
			t.Fatal(err)
		}
	}
}

// Trust is set, and there is no run and never was one. While the run record cannot be written (a full disk,
// a read-only file system, its lock not to be had), the panel's Cancel was answered 500 "... the end of the
// run could not be written down; cancel again" on both kinds of machine, although the pending action was
// stopped and no run was there to end (second review of the runs, U1). v0.8.0 answered 200, and so does this.
func TestCancelWithoutARunIsAnswered200WhileTheRecordCannotBeWritten(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 {
			t.Fatalf("cancel with nothing pending and a record that can be written: %d %v", st, b)
		}
		lockInTheWay(t, r)
		r.pass(11 * time.Minute) // the look at the clock every ten minutes: the write fails
		if !strings.Contains(r.audit.String(), "the run record could not be written") {
			t.Fatal("the record could be written: the test tests nothing")
		}
		if run := r.block()["run"]; run != nil {
			t.Fatalf("a run: %v", run)
		}
		for i := 0; i < 2; i++ {
			if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 {
				t.Fatalf("cancel %d on a machine without any run whose record cannot be written: %d %v", i, st, b)
			}
		}
		if n := strings.Count(r.audit.String(), "the run record could not be written"); n != 1 {
			t.Errorf("%d lines about the record in the checker's log, want 1", n)
		}
	})
}

// The other side, on both kinds of machine (R42 of the first review held it for Linux; for Windows no test
// did: A22 of the second): a run is armed and its end cannot be written down. The cancel is not answered 200,
// because a checker that starts again would find the run in the record; the checker that is running does not
// switch the machine off; and the cancel sent again, once the record can be written, is answered 200.
func TestCancelOfARunIsNotAnswered200WhileItsEndCannotBeWritten(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		r.arm(hRunA)
		free := lockInTheWay(t, r)
		for i := 0; i < 2; i++ {
			st, b := r.post("/power", map[string]any{"action": "cancel"})
			if st == 200 {
				t.Fatalf("cancel %d: the end of the run could not be written and the answer is %d %v", i, st, b)
			}
			if msg, _ := b["error"].(string); !strings.Contains(msg, "could not be written down") {
				t.Errorf("cancel %d: %d %v", i, st, b)
			}
		}
		r.pass(2000 * time.Second)
		if len(r.exec.Scheduled) != 0 {
			t.Fatalf("the machine switched itself off after a cancel: %v", r.exec.Scheduled)
		}
		free()
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 {
			t.Fatalf("the cancel sent again: %d %v", st, b)
		}
		if v := r.files.RunShow(); v.ID != "" {
			t.Errorf("the record after the cancel that was answered 200: %+v", v)
		}
		r.pass(2000 * time.Second)
		if len(r.exec.Scheduled) != 0 {
			t.Fatalf("switched off: %v", r.exec.Scheduled)
		}
	})
}
