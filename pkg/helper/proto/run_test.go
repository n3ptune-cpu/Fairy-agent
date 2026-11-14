package proto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

const tRun = "00000000000000d4"

// The pipe's part of a run: two verbs and the member "run" of power and apply_update, all of them version 3
// frames, each with its own strict schema. A helper from before runs refuses every one of them unread.
func TestRunRequests(t *testing.T) {
	ap := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{}}
	run, to, delay, within, shutdown, reboot, cancel, by := tRun, "19-abc", 30, 1500, "shutdown", "reboot", "cancel", "test"
	forGo, forPower := ForRunGo, VerbPower
	good := map[string]Request{
		"run_arm":                 {Verb: VerbRunArm, Approval: ap, By: &by},
		"run_go":                  {Verb: VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within, Approval: ap},
		"run_go without approval": {Verb: VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within},
		"challenge for run_go":    {Verb: VerbChallenge, For: &forGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within},
		"shutdown of a run":       {Verb: VerbPower, Action: &shutdown, DelayS: &delay, Run: &run, By: &by},
		"update of a run":         {Verb: VerbApplyUpdate, Run: &run, By: &by},
	}
	for name, req := range good {
		b, err := EncodeRequest(req)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if FrameVersion(req) != Version3 || !strings.Contains(string(b), `"v":3`) {
			t.Errorf("%s is not a version 3 request: %s", name, b)
		}
		if _, err := DecodeRequestV3(b); err != nil {
			t.Errorf("%s does not decode: %v", name, err)
		}
		if _, err := DecodeRequest(b); err == nil {
			t.Errorf("%s decodes as a plain frame", name)
		}
		if !Control(req.Verb) {
			t.Errorf("%s is not a control request (audit log, rate limit)", name)
		}
	}
	bad5, upper := 5, strings.ToUpper(tRun)
	for name, req := range map[string]Request{
		"run_arm without approval":            {Verb: VerbRunArm},
		"run_arm with a run":                  {Verb: VerbRunArm, Approval: ap, Run: &run},
		"run_go without within_s":             {Verb: VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &delay},
		"run_go with a delay under 10":        {Verb: VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &bad5, WithinS: &within},
		"run_go with delay_s":                 {Verb: VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within, DelayS: &delay},
		"reboot of a run":                     {Verb: VerbPower, Action: &reboot, DelayS: &delay, Run: &run},
		"cancel with a run":                   {Verb: VerbPower, Action: &cancel, Run: &run},
		"shutdown with a run and an approval": {Verb: VerbPower, Action: &shutdown, DelayS: &delay, Run: &run, Approval: ap},
		"update with a run and an approval":   {Verb: VerbApplyUpdate, Run: &run, Approval: ap},
		"shutdown with a run id that is none": {Verb: VerbPower, Action: &shutdown, DelayS: &delay, Run: &upper},
		"shutdown with to":                    {Verb: VerbPower, Action: &shutdown, DelayS: &delay, To: &to},
		"challenge for power with a run":      {Verb: VerbChallenge, For: &forPower, Action: &shutdown, DelayS: &delay, Run: &run},
		"challenge for run_go with delay_s":   {Verb: VerbChallenge, For: &forGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within, DelayS: &delay},
		"challenge for run_go without to":     {Verb: VerbChallenge, For: &forGo, Run: &run, ShutdownDelayS: &delay, WithinS: &within},
		"challenge for run_arm":               {Verb: VerbChallenge, For: ptrS(VerbRunArm)},
		"fan_auto with a run":                 {Verb: VerbFanAuto, Run: &run},
	} {
		if b, err := EncodeRequest(req); err == nil {
			t.Errorf("%s: encoded %s", name, b)
		}
		req.V = Version3
		b, _ := json.Marshal(req)
		if _, err := DecodeRequestV3(b); err == nil {
			t.Errorf("%s: decoded %s", name, b)
		}
	}
	// the request a challenge for run_go is for
	ar, ok := ApprovalRequestOf(good["challenge for run_go"])
	if canon, err := ar.Canonical(); !ok || err != nil || canon != "run_go run="+tRun+" to=19-abc shutdown_delay_s=30 within_s=1500" {
		t.Errorf("ApprovalRequestOf: %q, %v, %v", canon, ok, err)
	}
	// the two verbs themselves are not requests the ordinary check is asked about
	for _, v := range []string{"run_arm", "run_go"} {
		if _, ok := ApprovalRequestOf(good[v]); ok {
			t.Errorf("%s is handed to the ordinary approval check", v)
		}
	}
	// the refusals of a run have their statuses, and the reason travels with them
	for code, st := range map[string]int{api.CodeApprovalOff: 409, api.CodeRunRefused: 409, api.CodeRunUnavailable: 503} {
		if got := Fail(code, "x").Status; got != st {
			t.Errorf("Fail(%s) = %d, want %d", code, got, st)
		}
	}
	b, _ := json.Marshal(Response{Status: 409, Code: api.CodeRunRefused, Reason: api.RunReasonTooLate})
	if r, err := DecodeResponse(b); err != nil || r.Reason != api.RunReasonTooLate {
		t.Errorf("reason: %+v, %v", r, err)
	}
}

func ptrS(s string) *string { return &s }
