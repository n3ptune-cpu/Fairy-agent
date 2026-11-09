package agent

import (
	"context"
	"errors"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Migrator is the Windows self-migration from LocalSystem to NT SERVICE\fairy-agent (cmd/fairy-agent,
// pkg/agent/migrate): its /metrics "migration" block, and its run once the agent listens.
type Migrator interface {
	Status() api.MigrationStatus
	// Busy: it is changing the services now (the panel's Update waits meanwhile).
	Busy() bool
	Run(ctx context.Context, h MigrationHooks)
}

// MigrationHooks are the parts of the running agent the migration needs.
type MigrationHooks struct {
	// FansAuto hands the fans back to the BMC's automatic mode when this process controls them itself (nil:
	// no fan control here, or the helper does it).
	FansAuto func(ctx context.Context) error
	// Busy says why not now ("": go ahead): an update being downloaded or installed, a power action pending.
	Busy func() string
}

var errMigrating = errors.New("the agent is moving to its own account NT SERVICE\\fairy-agent; Update works again in a few minutes")

func (a *Agent) migrationHooks() MigrationHooks {
	h := MigrationHooks{Busy: func() string {
		if a.d.Updater != nil {
			if st := a.d.Updater.Status(); st.State == "downloading" || st.State == "applying" {
				return "an update is " + st.State
			}
		}
		if a.d.Power != nil && a.d.Power.Scheduled() {
			return "a shutdown, reboot or sleep is scheduled"
		}
		return ""
	}}
	if f, ok := a.d.Fan.(*Fan); ok && f != nil {
		h.FansAuto = func(ctx context.Context) error {
			_, err := f.Auto(ctx, "migration to NT SERVICE\\fairy-agent", false)
			return err
		}
	}
	return h
}
