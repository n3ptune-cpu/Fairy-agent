//go:build linux

package collect

import (
	"context"
	"os"
	"testing"
	"time"
)

// The real collector on the machine running the tests: values must be present and sane.
func TestLinuxCollector(t *testing.T) {
	c := NewSystem()
	st := c.Static()
	if st.Platform.System != "Linux" || st.Logical < 1 || st.Hostname == "" {
		t.Fatalf("%+v", st)
	}
	time.Sleep(600 * time.Millisecond)
	s := c.Sample(context.Background())
	if s.CPUPercent == nil || *s.CPUPercent < 0 || *s.CPUPercent > 100 || s.Memory.Total <= 0 || s.Memory.Used <= 0 ||
		s.UptimeS == nil || len(s.LoadAvg) != 3 {
		t.Fatalf("%+v", s)
	}
	procs, total, err := c.Processes(context.Background(), ProcOptions{Cmdline: true, MemTotal: s.Memory.Total, Interval: 100 * time.Millisecond})
	if err != nil || total < 1 || len(procs) == 0 {
		t.Fatal(total, len(procs), err)
	}
	me := false
	for _, p := range procs {
		if p.PID == os.Getpid() {
			me = p.Name != nil && p.RSS != nil && *p.RSS > 0 && p.CPUPercent != nil && p.CreateTime != nil && p.Cmdline != nil
		}
	}
	if !me {
		t.Fatal("own process missing or incomplete")
	}
}
