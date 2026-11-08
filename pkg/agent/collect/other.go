//go:build !linux && !windows

package collect

import (
	"context"
	"os"
	"runtime"
)

type other struct{ static Static }

// NewSystem returns a minimal collector on systems fairy-agent does not support (it builds, reports the
// hostname and CPU count, and nothing else).
func NewSystem() Collector {
	h, _ := os.Hostname()
	return &other{Static{Hostname: h, Platform: Platform{System: runtime.GOOS, Pretty: runtime.GOOS}, Logical: numCPU()}}
}

func (o *other) Static() Static                { return o.static }
func (o *other) Sample(context.Context) Sample { return Sample{} }
func (o *other) Processes(context.Context, ProcOptions) ([]Process, int, error) {
	return nil, 0, nil
}
