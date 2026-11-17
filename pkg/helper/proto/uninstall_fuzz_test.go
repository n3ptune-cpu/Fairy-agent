package proto

import "testing"

// The helper's pipe decoder with the verb uninstall: whatever passes DecodeRequest / DecodeRequestV3 as an
// uninstall carries who asked and the approval and nothing else, and a challenge for it carries no member, so
// nothing in a frame can choose what is removed or stand in for the approval (a run, a mode, an action).
func FuzzUninstallFrames(f *testing.F) {
	f.Add(`{"v":3,"verb":"uninstall","by":"panel 100.64.0.10","approval":{"token":"a.b.c","entries":[]}}`)
	f.Add(`{"v":1,"verb":"uninstall","by":"x"}`)
	f.Add(`{"v":3,"verb":"uninstall","approval":{"token":"a.b.c","entries":[]},"run":"00000000000000aa"}`)
	f.Add(`{"v":3,"verb":"uninstall","approval":{"token":"a.b.c","entries":[]},"action":"shutdown","delay_s":10}`)
	f.Add(`{"v":3,"verb":"uninstall","approval":{"token":"a.b.c","entries":[]},"approval":{"token":"d.e.f","entries":[]}}`)
	f.Add(`{"v":3,"verb":"uninstall","Approval":{"token":"a.b.c","entries":[]},"keep_data":false}`)
	f.Add(`{"v":3,"verb":"challenge","for":"uninstall"}`)
	f.Add(`{"v":3,"verb":"challenge","for":"uninstall","mode":"full"}`)
	f.Add(`{"v":3,"verb":"challenge","for":"uninstall","trust_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		for _, dec := range []func([]byte) (Request, error){DecodeRequest, DecodeRequestV3} {
			r, err := dec([]byte(raw))
			if err != nil {
				continue
			}
			others := r.Zone != nil || r.Percent != nil || r.Mode != nil || r.Action != nil || r.DelayS != nil || r.Trust != nil ||
				r.TrustHash != nil || r.Run != nil || r.To != nil || r.ShutdownDelayS != nil || r.WithinS != nil
			switch {
			case r.Verb == VerbUninstall && (others || r.For != nil):
				t.Fatalf("an uninstall with another member passed: %q", raw)
			case r.Verb == VerbChallenge && r.For != nil && *r.For == VerbUninstall && (others || r.Approval != nil):
				t.Fatalf("a challenge for uninstall with a member passed: %q", raw)
			}
		}
	})
}
