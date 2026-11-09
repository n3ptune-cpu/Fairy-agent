//go:build !windows

package collect

// ProcGPU is Windows only (see procgpu_windows.go).
type ProcGPU struct{}

// NewProcGPU is nil off Windows.
func NewProcGPU() *ProcGPU { return nil }

// ComputeAppsFor is nil off Windows.
func (*ProcGPU) ComputeAppsFor([]GPU) map[int][]int64 { return nil }
