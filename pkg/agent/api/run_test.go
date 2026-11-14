package api

import (
	"strings"
	"testing"
)

func runArm(run string, valid, wait, notice int) ApprovalRequest {
	return ApprovalRequest{Verb: ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}
}

func runGo(run, to string, delay, within int) ApprovalRequest {
	return ApprovalRequest{Verb: ApproveRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within}
}

const testRun = "0123456789abcdef"

// The two texts of a run, exactly as the design writes them, and the limits of every number in them: a
// request outside them has no canonical form, so nothing can be signed for it and nothing accepted.
func TestRunCanonical(t *testing.T) {
	for _, c := range []struct {
		req  ApprovalRequest
		want string
	}{
		{runArm(testRun, 420, 960, 120), "run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=120"},
		{runArm(testRun, 120, 120, 30), "run_arm run=0123456789abcdef valid_s=120 wait_s=120 notice_s=30"},
		{runArm(testRun, 600, 3600, 600), "run_arm run=0123456789abcdef valid_s=600 wait_s=3600 notice_s=600"},
		{runGo(testRun, "19-abc1234", 30, 1500), "run_go run=0123456789abcdef to=19-abc1234 shutdown_delay_s=30 within_s=1500"},
		{runGo(testRun, "-", 10, 300), "run_go run=0123456789abcdef to=- shutdown_delay_s=10 within_s=300"},
		{runGo(testRun, "v0.9.0_x+y", 600, 1800), "run_go run=0123456789abcdef to=v0.9.0_x+y shutdown_delay_s=600 within_s=1800"},
	} {
		got, err := c.req.Canonical()
		if err != nil || got != c.want {
			t.Errorf("Canonical(%s) = %q, %v", c.want, got, err)
		}
		if len(got) > MaxApprovalRequest {
			t.Errorf("%q is longer than an entry's request may be", got)
		}
		back, err := ParseRunRequest(got)
		if err != nil {
			t.Errorf("ParseRunRequest(%q): %v", got, err)
			continue
		}
		if again, _ := back.Canonical(); again != got || back.Verb != c.req.Verb {
			t.Errorf("ParseRunRequest(%q) reads back as %q", got, again)
		}
	}
	long := strings.Repeat("9", MaxRunVersion)
	if got, err := runGo(testRun, long, 600, 1800).Canonical(); err != nil || len(got) > MaxApprovalRequest {
		t.Errorf("the longest confirmation: %d bytes, %v", len(got), err)
	}
	extra := runArm(testRun, 420, 960, 120)
	extra.DelayS = ip(5)
	missing := runGo(testRun, "19-a", 30, 1500)
	missing.WithinS = nil
	for name, req := range map[string]ApprovalRequest{
		"valid_s under": runArm(testRun, 119, 960, 120), "valid_s over": runArm(testRun, 2101, 960, 120),
		"wait_s under": runArm(testRun, 420, 119, 120), "wait_s over": runArm(testRun, 420, 3601, 120),
		"notice_s under": runArm(testRun, 420, 960, 29), "notice_s over": runArm(testRun, 420, 960, 601),
		"run short": runArm("0123456789abcde", 420, 960, 120), "run upper": runArm("0123456789ABCDEF", 420, 960, 120),
		"run long": runArm(testRun+"0", 420, 960, 120), "run space": runArm("0123456789abcde ", 420, 960, 120),
		"arm with delay_s": extra, "go without within_s": missing,
		"delay under": runGo(testRun, "19-a", 9, 1500), "delay over": runGo(testRun, "19-a", 601, 1500),
		"within under": runGo(testRun, "19-a", 30, 299), "within over": runGo(testRun, "19-a", 30, 3601),
		"to empty": runGo(testRun, "", 30, 1500), "to space": runGo(testRun, "19 a", 30, 1500), "to equals": runGo(testRun, "a=b", 30, 1500),
		"to long": runGo(testRun, long+"9", 30, 1500), "to dash first": runGo(testRun, "-19", 30, 1500), "to two dashes": runGo(testRun, "--", 30, 1500),
		"to newline": runGo(testRun, "19\n", 30, 1500), "to slash": runGo(testRun, "19/a", 30, 1500),
	} {
		if got, err := req.Canonical(); err == nil {
			t.Errorf("%s: canonical %q, want an error", name, got)
		}
	}
	// the members of a run request belong to no other request
	shutdown := ApprovalRequest{Verb: ApprovePower, Action: sp("shutdown"), DelayS: ip(60), Run: sp(testRun)}
	if got, err := shutdown.Canonical(); err == nil {
		t.Errorf("power with run has a canonical form: %q", got)
	}
}

// ParseRunRequest takes the canonical text and nothing that only looks like it.
func TestParseRunRequestRefuses(t *testing.T) {
	good := "run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=120"
	if _, err := ParseRunRequest(good); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"", "run_arm", good + " ", " " + good, strings.Replace(good, " ", "  ", 1), good + " x=1",
		"run_arm run=0123456789abcdef valid_s=0420 wait_s=960 notice_s=120",
		"run_arm run=0123456789abcdef valid_s=+420 wait_s=960 notice_s=120",
		"run_arm run=0123456789abcdef valid_s=420 notice_s=120 wait_s=960",
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=12000000000000000000",
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=",
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=1e2",
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=5",
		"run_arm run=0123456789ABCDEF valid_s=420 wait_s=960 notice_s=120",
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice=120",
		"RUN_ARM run=0123456789abcdef valid_s=420 wait_s=960 notice_s=120",
		"run_go run=0123456789abcdef valid_s=420 wait_s=960 notice_s=120",
		"run_go run=0123456789abcdef to= shutdown_delay_s=30 within_s=1500",
		"run_go run=0123456789abcdef to=19-a shutdown_delay_s=30 within_s=1500 ",
		"run_go run=0123456789abcdef to=19-a within_s=1500 shutdown_delay_s=30",
		"power action=shutdown delay_s=60", "apply_update", "trust_set hash=x",
		good + strings.Repeat("0", MaxApprovalRequest),
	} {
		if r, err := ParseRunRequest(text); err == nil {
			t.Errorf("ParseRunRequest(%q) = %+v, want an error", text, r)
		}
	}
}

// FuzzParseRunRequest: whatever text is accepted is the canonical text of the request it is read as, and the
// parser never panics.
func FuzzParseRunRequest(f *testing.F) {
	for _, s := range []string{
		"run_arm run=0123456789abcdef valid_s=420 wait_s=960 notice_s=120",
		"run_go run=0123456789abcdef to=19-abc1234 shutdown_delay_s=30 within_s=1500",
		"run_go run=0123456789abcdef to=- shutdown_delay_s=10 within_s=300",
		"run_arm run= valid_s= wait_s= notice_s=", "run_go  run=x", "run_arm run=0123456789abcdef valid_s=-1 wait_s=960 notice_s=120",
		"power action=shutdown delay_s=60", "", " ", "run_arm\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		r, err := ParseRunRequest(text)
		if err != nil {
			return
		}
		canon, cerr := r.Canonical()
		if cerr != nil || canon != text {
			t.Fatalf("accepted %q, which is not canonical (%q, %v)", text, canon, cerr)
		}
		if r.Verb != ApproveRunArm && r.Verb != ApproveRunGo {
			t.Fatalf("accepted %q as %s", text, r.Verb)
		}
		if _, err := ApprovalNonce([]MachineEntry{{MachineID: "test-machine-AAAAAAAAAAAA", Challenge: vectorChallenge(1), Request: text}}); err != nil {
			t.Fatalf("accepted %q, which cannot be an entry: %v", text, err)
		}
	})
}

// ApprovalProto is what it was: a panel of build 14 compares it for equality, and a machine that said another
// number would have its approvals switched off there. What is new is said by "runs".
func TestApprovalProtoStaysAndRunsIsOne(t *testing.T) {
	if ApprovalProto != 2 {
		t.Errorf("ApprovalProto = %d, want 2", ApprovalProto)
	}
	if ApprovalRuns != 1 {
		t.Errorf("ApprovalRuns = %d, want 1", ApprovalRuns)
	}
}

// The ceilings the owner was told: a ticket is good for 7 minutes by default and never for more than 10, the
// confirmation on disk for 30 minutes at most. (The agent took valid_s up to 2100 and within_s up to 3600:
// review of fd6d3be, T4.)
func TestRunCeilings(t *testing.T) {
	if RunValidMinS != 120 || RunValidMaxS != 600 || RunWithinMinS != 300 || RunWithinMaxS != 1800 {
		t.Fatalf("valid_s %d-%d, within_s %d-%d; want 120-600 and 300-1800", RunValidMinS, RunValidMaxS, RunWithinMinS, RunWithinMaxS)
	}
	if RunWaitMinS != 120 || RunWaitMaxS != 3600 || RunNoticeMinS != 30 || RunNoticeMaxS != 600 || RunShutdownDelayMinS != 10 || RunShutdownDelayMaxS != 600 || RunArmUptimeS != 600 {
		t.Fatal("a limit that was not to change has changed")
	}
	run := "00000000000000aa"
	arm := func(valid, wait, notice int) error {
		_, err := ApprovalRequest{Verb: ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}.Canonical()
		return err
	}
	goes := func(delay, within int) error {
		to := "-"
		_, err := ApprovalRequest{Verb: ApproveRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within}.Canonical()
		return err
	}
	for _, c := range []struct {
		what string
		err  error
		ok   bool
	}{
		{"valid_s 119", arm(119, 960, 120), false}, {"valid_s 120", arm(120, 960, 120), true}, {"valid_s 600", arm(600, 960, 120), true},
		{"valid_s 601", arm(601, 960, 120), false}, {"valid_s 2100", arm(2100, 960, 120), false},
		{"within_s 299", goes(30, 299), false}, {"within_s 300", goes(30, 300), true}, {"within_s 1800", goes(30, 1800), true},
		{"within_s 1801", goes(30, 1801), false}, {"within_s 3600", goes(30, 3600), false},
		// what the panel sends by default fits: a ticket valid for 7 minutes, a wait of 16 minutes (and up to
		// 300 + 1800 + 60 s with its longest confirm_wait_s), a notice of 2 minutes, 30 minutes for the confirmation
		{"the panel's defaults", arm(420, 960, 120), true}, {"the panel's longest wait", arm(420, 2160, 600), true}, {"the panel's confirmation", goes(30, 1800), true},
	} {
		if (c.err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", c.what, c.err, c.ok)
		}
	}
	for _, text := range []string{"run_arm run=00000000000000aa valid_s=601 wait_s=960 notice_s=120", "run_go run=00000000000000aa to=- shutdown_delay_s=30 within_s=1801"} {
		if _, err := ParseRunRequest(text); err == nil {
			t.Errorf("%q has a canonical form", text)
		}
	}
}
