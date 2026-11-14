package approvaltest

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// EarlierBoot gives the machine with these files the run record it has from a boot before the one a test
// plays in: the checker made it when it first looked with trust set, at the time at (a day before the test's
// clock, say), in a boot with another id.
//
// A run record that is made anew closes its boot for tickets and takes none that was signed before. On a real
// machine that is the boot in which trust was set or the agent was updated; the machine a run wakes has its
// record from before. A test that wants a ticket taken calls this after the trust is set and before the
// checker under test is asked anything of a run.
func EarlierBoot(files approval.Files, at time.Time) error {
	g := approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent, Runs: true,
		Now:    func() time.Time { return at },
		Uptime: func() (time.Duration, error) { return time.Hour, nil },
		BootID: func() (string, error) { return "the-boot-before", nil },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil))})
	approval.NewRunWatch(g, approval.RunHooks{}).Tick()
	if v := files.RunShow(); !v.Exists || v.Err != nil {
		return errors.New("approvaltest: no run record was made (is the trust set?)")
	}
	return nil
}
