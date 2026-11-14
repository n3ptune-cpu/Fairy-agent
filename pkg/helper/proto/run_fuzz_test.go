package proto

// The helper's pipe decoder with the run verbs and the member "run" (from the independent review of fd6d3be).
// What the helper relies on after DecodeRequestV3: run_go has a canonical text; a power or apply_update
// that names a run carries no approval, the run is a run id, and the power action is "shutdown"; run_arm
// carries an approval; nothing else carries run / to / shutdown_delay_s / within_s (but a challenge for run_go).

import (
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

func FuzzRunFrames(f *testing.F) {
	f.Add(`{"v":3,"verb":"run_go","run":"00000000000000aa","to":"1.2.3","shutdown_delay_s":30,"within_s":300,"approval":{"token":"a.b.c","entries":[]}}`)
	f.Add(`{"v":3,"verb":"run_arm","approval":{"token":"a.b.c","entries":[]}}`)
	f.Add(`{"v":3,"verb":"power","action":"shutdown","delay_s":30,"run":"00000000000000aa"}`)
	f.Add(`{"v":3,"verb":"power","action":"reboot","delay_s":30,"run":"00000000000000aa"}`)
	f.Add(`{"v":3,"verb":"apply_update","run":"00000000000000aa","by":"x"}`)
	f.Add(`{"v":3,"verb":"challenge","for":"run_go","run":"00000000000000aa","to":"-","shutdown_delay_s":10,"within_s":3600}`)
	f.Add(`{"v":3,"verb":"challenge","for":"run_arm","run":"00000000000000aa"}`)
	f.Add(`{"v":3,"verb":"power","action":"shutdown","delay_s":30,"run":"00000000000000aa","Run":"00000000000000bb"}`)
	f.Add(`{"v":3,"verb":"power","action":"shutdown","delay_s":30,"run":"00000000000000aa","run":"00000000000000bb"}`)
	f.Add(`{"v":3,"verb":"run_go","run":"00000000000000aa","to":"1.2.3","shutdown_delay_s":3e1,"within_s":300}`)
	f.Add(`{"v":3,"verb":"run_go","run":"00000000000000aa","to":"1.2.3","shutdown_delay_s":99999999999999999999,"within_s":-300}`)
	f.Fuzz(func(t *testing.T, raw string) {
		for _, dec := range []func([]byte) (Request, error){DecodeRequest, DecodeRequestV3} {
			r, err := dec([]byte(raw))
			if err != nil {
				continue
			}
			runMembers := r.Run != nil || r.To != nil || r.ShutdownDelayS != nil || r.WithinS != nil
			switch r.Verb {
			case VerbRunGo:
				if _, err := RunGoRequestOf(r).Canonical(); err != nil {
					t.Fatalf("run_go without a canonical text passed: %q", raw)
				}
			case VerbRunArm:
				if r.Approval == nil || runMembers {
					t.Fatalf("run_arm without approval or with run members passed: %q", raw)
				}
			case VerbPower:
				if r.To != nil || r.ShutdownDelayS != nil || r.WithinS != nil {
					t.Fatalf("power with members of run_go: %q", raw)
				}
				if r.Run != nil && (r.Approval != nil || api.CheckRunID(*r.Run) != nil || r.Action == nil || *r.Action != "shutdown") {
					t.Fatalf("power with a run that is not a plain shutdown of a run: %q", raw)
				}
			case VerbApplyUpdate:
				if r.To != nil || r.ShutdownDelayS != nil || r.WithinS != nil {
					t.Fatalf("apply_update with members of run_go: %q", raw)
				}
				if r.Run != nil && (r.Approval != nil || api.CheckRunID(*r.Run) != nil) {
					t.Fatalf("apply_update with run and approval: %q", raw)
				}
			case VerbChallenge:
				if r.For != nil && *r.For == ForRunGo {
					if _, err := RunGoRequestOf(r).Canonical(); err != nil {
						t.Fatalf("challenge for run_go without canonical text: %q", raw)
					}
				} else if runMembers {
					t.Fatalf("a challenge for another verb with run members: %q", raw)
				}
				if r.For != nil && *r.For == api.ApproveRunArm {
					t.Fatalf("a challenge for run_arm passed the decoder: %q", raw)
				}
			default:
				if runMembers {
					t.Fatalf("%s with run members passed: %q", r.Verb, raw)
				}
			}
			if (r.Run != nil || r.Verb == VerbRunArm || r.Verb == VerbRunGo) && FrameVersion(r) != Version3 {
				t.Fatalf("a run request in a version 2 frame: %q", raw)
			}
		}
	})
}
