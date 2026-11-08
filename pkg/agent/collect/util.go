package collect

import (
	"runtime"
	"strconv"
	"strings"
)

// CountCPUList counts the CPUs in a kernel CPU list such as "0-7,9" (0 if it does not parse).
func CountCPUList(s string) int {
	n := 0
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			return 0
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil || hi < lo {
				return 0
			}
		}
		n += hi - lo + 1
	}
	return n
}

func numCPU() int { return runtime.NumCPU() }
