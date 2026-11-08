//go:build !windows

package collect

// coreTempRead is nil: Core Temp is a Windows program (Linux reads the CPU's sensors through hwmon).
var coreTempRead func() ([]byte, string, error)
