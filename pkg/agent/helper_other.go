//go:build !windows

package agent

// systemHelper: the elevated helper exists only on Windows (Linux grants the few extra rights with polkit,
// udev and tmpfiles rules instead).
func systemHelper(*Config) *HelperClient { return nil }

func isAccessDenied(error) bool { return false }
