package agent

import (
	"context"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

type fakeMigration struct{ st api.MigrationStatus }

func (f fakeMigration) Status() api.MigrationStatus { return f.st }

func TestMigrationInMetrics(t *testing.T) {
	r := newRig(t, "")
	if _, m := r.do(t, "GET", "/metrics", readTok, nil); m["migration"] != nil {
		t.Fatal("migration block without a migrator (Linux)")
	}
	r.a.d.Migration = fakeMigration{api.MigrationStatus{State: api.MigrationNeedsAdmin, Account: "LocalService", Command: "x"}}
	r.a.mu.Lock()
	r.a.cache = nil
	r.a.mu.Unlock()
	_, m := r.do(t, "GET", "/metrics", readTok, nil)
	mb, ok := m["migration"].(map[string]any)
	if !ok || mb["state"] != "needs_admin" || mb["account"] != "LocalService" || mb["command"] != "x" {
		t.Fatalf("%v", m["migration"])
	}
}

func TestMigrationHooks(t *testing.T) {
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\n")
	h := r.a.migrationHooks()
	if h.FansAuto == nil || h.Busy() != "" {
		t.Fatalf("hooks %+v busy %q", h, h.Busy())
	}
	// a fixed duty set: the hook hands the fans back to the BMC's automatic mode
	ctx := context.Background()
	if err := ipmi.SetFanMode(ctx, r.bmc, "full"); err != nil {
		t.Fatal(err)
	}
	if err := h.FansAuto(ctx); err != nil {
		t.Fatal(err)
	}
	if mode, _ := ipmi.GetFanMode(ctx, r.bmc); mode != r.a.cfg.FanControl.AutoMode {
		t.Fatalf("mode %s after FansAuto", mode)
	}
	d := 600
	if st, b := r.a.d.Power.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 200 && st != 202 {
		t.Fatal(st, b)
	}
	if h.Busy() == "" {
		t.Fatal("not busy with a reboot scheduled")
	}
	if r2 := newRig(t, ""); r2.a.migrationHooks().FansAuto != nil {
		t.Fatal("FansAuto without fan control")
	}
}
