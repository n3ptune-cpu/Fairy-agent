package devices

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// hostileUpsd answers LIST UPS / LIST VAR like upsd, then misbehaves as told.
func hostileUpsd(t *testing.T, misbehave func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				misbehave(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestNUTGoodReply(t *testing.T) {
	port := hostileUpsd(t, func(c net.Conn) {
		fmt.Fprint(c, "BEGIN LIST VAR ups\nVAR ups ups.status \"OL\"\nVAR ups battery.charge \"100\"\nEND LIST VAR ups\n")
	})
	got, err := NUTReadAll(context.Background(), "127.0.0.1", port, "", "", 2*time.Second, []string{"ups"})
	if err != nil || len(got) != 1 || got[0].Vars["ups.status"] != "OL" {
		t.Fatal(got, err)
	}
}

// A hostile upsd sending one endless line, or endless short lines, must not grow the agent's memory: the read
// stops at NUTMaxLine / NUTMaxReply with a clear error.
func TestNUTBoundsHostileReplies(t *testing.T) {
	endless := func(chunk string) func(net.Conn) {
		return func(c net.Conn) {
			buf := []byte(strings.Repeat(chunk, 4096/len(chunk)))
			for i := 0; i < 64<<20/len(buf); i++ { // up to 64 MiB, far more than the limits
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}
	}
	for name, tc := range map[string]struct {
		upsd func(net.Conn)
		want string
	}{
		"one endless line": {endless("A"), "longer than"},
		"endless VAR lines": {func(c net.Conn) {
			fmt.Fprint(c, "BEGIN LIST VAR ups\n")
			endless("VAR ups x \"1\"\n")(c)
		}, "too"},
	} {
		port := hostileUpsd(t, tc.upsd)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := NUTReadAll(context.Background(), "127.0.0.1", port, "", "", 5*time.Second, []string{"ups"})
		runtime.ReadMemStats(&after)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
		if grown := int64(after.TotalAlloc) - int64(before.TotalAlloc); grown > 8<<20 {
			t.Fatalf("%s: allocated %d bytes", name, grown)
		}
	}
}

func TestNUTCapsUPSList(t *testing.T) {
	port := hostileUpsd(t, func(c net.Conn) {
		var b strings.Builder
		b.WriteString("BEGIN LIST UPS\n")
		for i := 0; i < 500; i++ {
			fmt.Fprintf(&b, "UPS u%d \"x\"\n", i)
		}
		b.WriteString("END LIST UPS\n")
		fmt.Fprint(c, b.String())
		r := bufio.NewReader(c)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			name := strings.TrimSpace(strings.TrimPrefix(l, "LIST VAR "))
			fmt.Fprintf(c, "BEGIN LIST VAR %s\nEND LIST VAR %s\n", name, name)
		}
	})
	got, err := NUTReadAll(context.Background(), "127.0.0.1", port, "", "", 5*time.Second, nil)
	if err != nil || len(got) != NUTMaxUPS {
		t.Fatal(len(got), err)
	}
}
