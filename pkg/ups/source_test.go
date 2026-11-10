package ups

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// fakeUpsd is a upsd with one UPS "cp" that reports these variables (read-only protocol: LIST UPS, LIST VAR).
func fakeUpsd(t *testing.T, vars map[string]string) int {
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
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch line = strings.TrimSpace(line); {
					case line == "LIST UPS":
						fmt.Fprint(c, "BEGIN LIST UPS\nUPS cp \"CyberPower\"\nEND LIST UPS\n")
					case strings.HasPrefix(line, "LIST VAR "):
						name := strings.TrimPrefix(line, "LIST VAR ")
						fmt.Fprintf(c, "BEGIN LIST VAR %s\n", name)
						for k, v := range vars {
							fmt.Fprintf(c, "VAR %s %s \"%s\"\n", name, k, v)
						}
						fmt.Fprintf(c, "END LIST VAR %s\n", name)
					default:
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Audit 3, L11: `VAR cp ups.realpower "NaN"` made the row unwritable, RowMap returned an empty map and the UPS
// dropped out of the answer without an error. Now the row arrives with its state and the value is unknown.
func TestNaNFromUpsdKeepsTheRow(t *testing.T) {
	for _, bad := range []string{"NaN", "Inf", "-Inf", "1e999"} {
		port := fakeUpsd(t, map[string]string{"ups.status": "OB LB", "battery.charge": "9", "battery.runtime": "-5",
			"ups.realpower": bad, "ups.load": "250"})
		src, err := Build(map[string]any{"id": "rack", "host": "127.0.0.1", "port": port})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := src.Read(context.Background(), 2*time.Second)
		if err != nil || len(rows) != 1 {
			t.Fatal(bad, rows, err)
		}
		r := rows[0]
		if r["name"] != "cp" || r["ok"] != true || r["state"] != "low_battery" || r["battery_charge"] != 9.0 ||
			r["watts"] != nil || r["battery_runtime_s"] != nil || r["load_percent"] != 250.0 || r["description"] != "CyberPower" {
			t.Errorf("ups.realpower %q: %v", bad, r)
		}
		if _, err := json.Marshal(rows); err != nil {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A row that cannot be written (built by hand: UPSFromVars never returns one) is a failed row with its name.
func TestRowMapFailedRowIsVisible(t *testing.T) {
	nan := math.NaN()
	m := RowMap(devices.UPSRow{Name: "cp", State: "online", OK: true, Watts: &nan})
	if m["name"] != "cp" || m["ok"] != false || m["error"] != "ups reports impossible values" {
		t.Fatalf("%v", m)
	}
	if _, err := json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	good := 225.0
	m = RowMap(devices.UPSRow{Name: "cp", State: "online", OK: true, Watts: &good, Flags: []string{"online"}})
	if m["name"] != "cp" || m["ok"] != true || m["watts"] != 225.0 || m["state"] != "online" || m["error"] != nil {
		t.Fatalf("%v", m)
	}
}
