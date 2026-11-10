package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// Requests that ask at the same time share one listing, a finished listing answers for a second, and a request
// that gives up does not stop the listing for the others (review N6: listings used to be made one per request,
// one after the other).
func TestProcessListingIsShared(t *testing.T) {
	r := newRig(t, "")
	release := make(chan struct{})
	var listings atomic.Int64
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release, calls: &listings}

	// one request gives up while the listing is being made
	gone, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		_, err := r.a.processList(gone)
		gaveUp <- err
	}()
	var wg sync.WaitGroup
	lists := make([]*procList, 10)
	for i := range lists {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := r.a.processList(context.Background())
			if err != nil {
				t.Error(err)
			}
			lists[i] = l
		}()
	}
	for listings.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-gaveUp; err == nil {
		t.Fatal("a request that gave up got a listing")
	}
	close(release)
	wg.Wait()
	for i, l := range lists {
		if l == nil || l != lists[0] || len(l.rows) != 4 || l.total != 212 {
			t.Fatalf("request %d: %+v", i, l)
		}
	}
	if n := listings.Load(); n != 1 {
		t.Fatalf("%d listings for 11 requests at the same time", n)
	}
	// within a second: the same listing, /proc is not read again
	st, b := r.do(t, "GET", "/processes?sort=mem&limit=2", readTok, nil)
	if st != 200 || len(b["processes"].([]any)) != 2 || b["total_processes"] != 212.0 || listings.Load() != 1 {
		t.Fatal(st, b, listings.Load())
	}
	if first := b["processes"].([]any)[0].(map[string]any); first["pid"] != 6000.0 {
		t.Fatal("sorted by memory, the first row is", first)
	}
	// sorting one answer does not change the shared rows for the next
	st, b = r.do(t, "GET", "/processes?sort=cpu&limit=1", readTok, nil)
	if first := b["processes"].([]any)[0].(map[string]any); st != 200 || first["pid"] != 6000.0 || listings.Load() != 1 {
		t.Fatal(st, b)
	}
	// older than a second: a new one
	r.a.procMu.Lock()
	r.a.procLast.at = time.Now().Add(-processMaxAge - time.Millisecond)
	r.a.procMu.Unlock()
	if st, _ := r.do(t, "GET", "/processes", readTok, nil); st != 200 || listings.Load() != 2 {
		t.Fatal(st, listings.Load())
	}
}

// A listing that failed is not kept: the next request tries again.
func TestProcessListingErrorIsNotKept(t *testing.T) {
	r := newRig(t, "")
	release := make(chan struct{})
	var listings atomic.Int64
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release, calls: &listings}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.a.processList(ctx); err == nil {
		t.Fatal("no error from a listing that never came back")
	}
	close(release)
	if st, b := r.do(t, "GET", "/processes", readTok, nil); st != 200 {
		t.Fatal(st, b)
	}
}

// A kept listing holds the rows any request can be answered with and no more: the 200 highest by CPU, by
// memory and by GPU memory.
func TestTopProcesses(t *testing.T) {
	var all []collect.Process
	for i := 0; i < 5000; i++ {
		p := collect.Process{PID: i + 1, CPUPercent: collect.P(float64(i % 977)), RSS: collect.P(int64((i * 7919) % 5003))}
		if i%50 == 0 {
			p.GPUMem = collect.P(int64(i))
		}
		all = append(all, p)
	}
	kept := topProcesses(append([]collect.Process(nil), all...), maxProcessRows)
	if len(kept) > 3*maxProcessRows || len(kept) < maxProcessRows {
		t.Fatal(len(kept))
	}
	for _, by := range []string{"cpu", "mem", "gpu"} {
		want := append([]collect.Process(nil), all...)
		SortProcesses(want, by)
		got := append([]collect.Process(nil), kept...)
		SortProcesses(got, by)
		for i := 0; i < maxProcessRows; i++ {
			if got[i].PID != want[i].PID {
				t.Fatalf("sort %s, row %d: pid %d, want %d", by, i, got[i].PID, want[i].PID)
			}
		}
	}
	// a short list is returned whole (as a copy)
	few := all[:3]
	if got := topProcesses(few, maxProcessRows); len(got) != 3 || &got[0] == &few[0] {
		t.Fatal(got)
	}
	if got := topProcesses(nil, maxProcessRows); len(got) != 0 {
		t.Fatal(got)
	}
}

// At most maxFanStatus /fan/status requests are in flight (each waits for the BMC); one more is told "busy" at
// once and holds no connection of the panel. /metrics and control requests have no such cap.
func TestSlowReadsHaveACap(t *testing.T) {
	r := newRig(t, fanYAML)
	for i := 0; i < maxFanStatus; i++ {
		r.a.fanStatuses <- struct{}{}
	}
	st, b := r.do(t, "GET", "/fan/status", readTok, nil)
	if st != 503 || b["code"] != BusyCode {
		t.Fatal(st, b)
	}
	if st, b := r.do(t, "GET", "/metrics", readTok, nil); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "standard"}); st != 200 {
		t.Fatal(st, b)
	}
	// without a token the cap is not even looked at
	if st, _ := r.do(t, "GET", "/fan/status", "", nil); st != 401 {
		t.Fatal(st)
	}
	<-r.a.fanStatuses
	if st, b := r.do(t, "GET", "/fan/status", readTok, nil); st != 200 {
		t.Fatal(st, b)
	}
	if len(r.a.fanStatuses) != maxFanStatus-1 {
		t.Fatal("a finished request kept its place:", len(r.a.fanStatuses))
	}
	if cap(r.a.procWaiters) != maxProcessWaiters || maxProcessWaiters+maxFanStatus >= MaxConnsPanel {
		t.Fatal(fmt.Sprint(cap(r.a.procWaiters), maxFanStatus, MaxConnsPanel))
	}
}

// optionProcs is a collector that keeps the options it was asked with.
type optionProcs struct {
	collect.Collector
	got chan collect.ProcOptions
}

func (o optionProcs) Processes(ctx context.Context, opt collect.ProcOptions) ([]collect.Process, int, error) {
	o.got <- opt
	return o.Collector.Processes(ctx, opt)
}

// Review N8: the server tells the collector how many rows a request can use and which rows it will add GPU
// memory to, so that the collector need not keep every process.
func TestProcessListingAsksForTheRowsItCanUse(t *testing.T) {
	r := newRig(t, "")
	got := make(chan collect.ProcOptions, 1)
	r.a.d.Collector = optionProcs{Collector: r.a.d.Collector, got: got}
	st, b := r.do(t, "GET", "/processes?sort=gpu&limit=200", readTok, nil)
	if st != 200 {
		t.Fatal(st, b)
	}
	o := <-got
	if o.Top != maxProcessRows || maxProcessRows != 200 || o.Keep == nil {
		t.Fatalf("%+v", o)
	}
	if !o.Keep(6000) || o.Keep(4120) { // 6000 is the one process with GPU memory (agenttest.GPU)
		t.Fatal("Keep does not name the processes with GPU memory")
	}
	rows := b["processes"].([]any)
	if first := rows[0].(map[string]any); first["pid"] != 6000.0 || first["gpu_mem"] == nil {
		t.Fatal(first)
	}
}
