package agent

// Audit 6, r4-a1-04: what Status answers while another call has the helper's one connection.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// holdingHelper answers the status question at once and holds every other request until release is closed
// (a fan change at a slow BMC).
type holdingHelper struct {
	mu       sync.Mutex
	statuses int
	entered  chan struct{}
	release  chan struct{}
}

func (h *holdingHelper) serve(conn net.Conn) {
	defer conn.Close()
	for {
		f, _, err := proto.ReadRequest(conn)
		if err != nil {
			return
		}
		var req struct {
			Verb string `json:"verb"`
		}
		_ = json.Unmarshal(f, &req)
		r := proto.OK(map[string]string{"mode": "auto"})
		if req.Verb == proto.VerbStatus {
			h.mu.Lock()
			h.statuses++
			h.mu.Unlock()
			r = proto.OK(proto.StatusData{Version: "test", Features: []string{api.FeatureFans}, Proto: proto.Version3})
		} else {
			h.entered <- struct{}{}
			<-h.release
		}
		b, _ := json.Marshal(r)
		if proto.WriteFrame(conn, b, proto.MaxResponse) != nil {
			return
		}
	}
}

func (h *holdingHelper) asked() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.statuses
}

type runningService struct{}

func (runningService) State() (string, error)      { return api.HelperRunning, nil }
func (runningService) Stop(context.Context) error  { return nil }
func (runningService) Start(context.Context) error { return nil }

// statusWithin asks for the status and reports whether the answer came within d.
func statusWithin(c *HelperClient, d time.Duration) (api.HelperStatus, bool, <-chan api.HelperStatus) {
	got := make(chan api.HelperStatus, 1)
	go func() { got <- c.Status(context.Background()) }()
	select {
	case st := <-got:
		return st, true, got
	case <-time.After(d):
		return api.HelperStatus{}, false, got
	}
}

func TestStatusDoesNotWaitBehindALongHelperCall(t *testing.T) {
	h := &holdingHelper{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c := NewHelperClient(func(context.Context) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go h.serve(a)
		return b, nil
	}, runningService{}, true)
	var clockMu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	pass := func(d time.Duration) { clockMu.Lock(); now = now.Add(d); clockMu.Unlock() }

	if st := c.Status(context.Background()); !st.Running() || h.asked() != 1 {
		t.Fatal(st, h.asked())
	}
	long := make(chan error, 1)
	go func() { // a fan change the BMC takes its time for
		by := "test"
		_, err := c.callWithTimeout(context.Background(), proto.Request{Verb: proto.VerbFanAuto, By: &by}, 25*time.Second)
		long <- err
	}()
	<-h.entered
	pass(time.Minute) // the copy of the status is older than two refreshes by now

	st, ok, _ := statusWithin(c, 2*time.Second)
	if !ok {
		t.Fatal("Status waited for the helper while another call had the connection (with it, every GET /metrics waits)")
	}
	if !st.Running() || st.Version != "test" || h.asked() != 1 {
		t.Fatalf("Status while the connection is taken: %+v, the helper was asked %d time(s); want the last copy", st, h.asked())
	}

	// a copy thrown away on purpose is asked for again, and that waits for the connection
	c.invalidate()
	_, ok, later := statusWithin(c, 150*time.Millisecond)
	if ok {
		t.Fatal("Status answered from a copy that was thrown away")
	}
	close(h.release)
	if err := <-long; err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-later:
		if !st.Running() || h.asked() != 2 {
			t.Fatalf("after the long call: %+v, asked %d time(s)", st, h.asked())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Status did not come back after the long call ended")
	}
	// the connection is free: an old copy is renewed as before
	pass(time.Minute)
	if st := c.Status(context.Background()); !st.Running() || h.asked() != 3 {
		t.Fatalf("an old copy with the connection free: %+v, asked %d time(s); want a new answer", st, h.asked())
	}
}
