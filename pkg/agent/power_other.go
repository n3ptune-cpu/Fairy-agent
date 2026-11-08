//go:build !linux && !windows

package agent

import (
	"errors"
	"time"
)

var errNoPower = errors.New("power actions are not supported on this system")

type noPower struct{}

// SystemPower returns an implementation that always refuses.
func SystemPower() PowerExec { return noPower{} }

func (noPower) Schedule(string, time.Duration, string) error { return errNoPower }
func (noPower) Cancel() error                                { return errNoPower }
