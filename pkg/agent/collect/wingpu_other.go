//go:build !windows

package collect

import (
	"context"
	"time"
)

// WinGPU is Windows only (see wingpu_windows.go).
type WinGPU struct{}

// NewWinGPU is nil off Windows.
func NewWinGPU(time.Duration, bool) *WinGPU { return nil }

// Names lists nothing.
func (*WinGPU) Names() []string { return nil }

// GPUs lists nothing.
func (*WinGPU) GPUs() []GPU { return nil }

// ComputeApps is nil.
func (*WinGPU) ComputeApps(context.Context) map[int][]int64 { return nil }
