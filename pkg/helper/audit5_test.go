package helper

// Audit 5, round 1: the helper's part of the fixes (the Windows path, where the helper is the one that checks
// and uses approvals up).

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// TestHelperRefusedShutdownDoesNotSpendTheOneAfterBoot (r1-a1-02, r1-a2-01), in the helper: with
// boot_shutdown_s set, a shutdown the helper refuses for a reason of its own (a delay under the helper's
// min_delay_s; a compromised or older agent may send one) used to spend the one shutdown without approval of
// this boot. It is recorded when a shutdown is really handed to the system.
func TestHelperRefusedShutdownDoesNotSpendTheOneAfterBoot(t *testing.T) {
	a := newApprovalRig(t)
	in := a.iss.Init()
	w := approval.DefaultFanWindowS
	nt, err := approval.NewTrust(approval.Trust{MachineID: in.MachineID, Issuer: in.Issuer, ClientID: in.ClientID, Keys: in.Keys, Users: in.Users,
		FanWindowS: &w, BootShutdownS: 900, SetBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.files.Replace(nt); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(a.audit, nil))
	a.srv = New(Parts{Version: "test", Power: a.power, MinDelayS: 30, Audit: log,
		Approval: approval.NewGate(approval.Options{Files: a.files, EnforcedBy: api.EnforcedByHelper, Log: log,
			Uptime: func() (time.Duration, error) { return 2 * time.Minute, nil }})})
	a.srv.limit = proto.NewLimiter(1000, 1000, time.Minute)
	mark := filepath.Join(filepath.Dir(a.files.Path), approval.BootMarkName)

	wantCode(t, "shutdown with a delay under the helper's minimum", a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":10,"by":"test"}`), 400, proto.CodeBadRequest)
	if _, err := os.Lstat(mark); err == nil {
		t.Fatal("the shutdown after boot was recorded for a request the helper refused")
	}
	if len(a.power.Scheduled) != 0 {
		t.Fatalf("scheduled: %v", a.power.Scheduled)
	}
	if resp := a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`); resp.Status != 200 {
		t.Fatalf("the one shutdown without approval after boot: %+v (the refused request before it used it up)", resp)
	}
	if _, err := os.Lstat(mark); err != nil {
		t.Fatalf("the accepted shutdown was not recorded: %v", err)
	}
	wantCode(t, "a second one", a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)
	wantCode(t, "reboot", a.call(t, `{"v":1,"verb":"power","action":"reboot","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)
	if len(a.power.Scheduled) != 1 {
		t.Fatalf("scheduled: %v", a.power.Scheduled)
	}
}

// TestHelperRefusedSleepCostsNoApproval: an approved sleep on a machine that cannot sleep is answered 409
// sleep_unavailable, and the approval is not looked at (the helper's log has no "accepted" for it).
func TestHelperRefusedSleepCostsNoApproval(t *testing.T) {
	a := newApprovalRig(t)
	a.power.NoSleep = "no S3 on this machine"
	a.srv = a.server()
	a.trust(t)
	req := powerReq("sleep", 60)
	req.Approval = a.approvalFor(t, req)
	for i := 0; i < 2; i++ {
		resp := a.v3(t, req)
		if resp.Status != 409 || resp.Code == api.CodeApprovalRefused {
			t.Fatalf("approved sleep on a machine that cannot sleep, try %d: %+v", i+1, resp)
		}
	}
	wantCode(t, "sleep without approval", a.call(t, `{"v":1,"verb":"power","action":"sleep","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)
	if log := a.audit.String(); strings.Contains(log, "approval: accepted") {
		t.Fatalf("the approval of a request the helper refused was used up:\n%s", log)
	}
}

// TestHelperChallengesCannotStarveCancel (r1-a2-03), on the pipe: the helper counted the verb challenge among
// its changes (30 a minute), with power cancel and fan_auto. An agent that passes on a full minute of challenge
// requests (control_rate_per_min can be 60) would have left the helper refusing a cancel. Challenges, and the
// two requests that only make things safer, now each have a budget of their own.
func TestHelperChallengesCannotStarveCancel(t *testing.T) {
	now := time.Unix(5000, 0)
	a := newApprovalRig(t)
	a.trust(t)
	a.srv.limit = proto.NewLimiter(proto.ReadsPerMinute, proto.ChangesPerMinute, time.Minute) // the helper's own limits
	a.srv.limit.Now = func() time.Time { return now }
	challenge := func() proto.Response {
		return a.v3(t, proto.Request{Verb: proto.VerbChallenge, For: ptr(proto.VerbApplyUpdate)})
	}
	for i := 0; i < proto.ChallengesPerMinute; i++ {
		if resp := challenge(); resp.Status == 429 && resp.Code == proto.CodeRateLimited {
			t.Fatalf("challenge %d was rate limited", i+1)
		}
	}
	wantCode(t, "one challenge too many", challenge(), 429, proto.CodeRateLimited)
	// the changes have their whole budget left, and use it up
	for i := 0; i < proto.ChangesPerMinute; i++ {
		wantCode(t, "fan_mode without approval", a.call(t, `{"v":1,"verb":"fan_mode","mode":"full","by":"test"}`), 403, api.CodeApprovalRequired)
	}
	wantCode(t, "one change too many", a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`), 429, proto.CodeRateLimited)
	// cancel and fan_auto are kept out by neither
	for i := 0; i < proto.SafePerMinute/2; i++ {
		if resp := a.call(t, `{"v":1,"verb":"power","action":"cancel","by":"agent"}`); resp.Status != 200 {
			t.Fatalf("cancel %d with the challenge and the change budget used up: %+v", i+1, resp)
		}
		if resp := a.call(t, `{"v":1,"verb":"fan_auto","by":"helper stop"}`); resp.Status != 200 {
			t.Fatalf("fan_auto %d with the challenge and the change budget used up: %+v", i+1, resp)
		}
	}
	wantCode(t, "one cancel too many", a.call(t, `{"v":1,"verb":"power","action":"cancel","by":"agent"}`), 429, proto.CodeRateLimited)
	if resp := a.call(t, `{"v":1,"verb":"status"}`); resp.Status != 200 {
		t.Fatalf("a read: %+v", resp)
	}
}
