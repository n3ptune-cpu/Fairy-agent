package agent

// Audit 4, T-02, the BMC relay's half: the Redfish answers of a relay target were decoded into generic JSON
// with a limit of 1 MiB, which costs about 50 times that in memory. The agent has 64 MiB.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// maxBMCRequestCost is what one /bmc/power request may allocate in all, whatever the BMC answers (a request
// asks the BMC up to four times). Before the fix one answer of 1 MiB of {"":0} allocated 73 MiB.
const maxBMCRequestCost = 16 << 20

func TestBMCRelayHostileRedfishAnswerCostsLittle(t *testing.T) {
	const systems = `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"x":[`
	const system = `{"PowerState":"On","x":[`
	chain := func(open, leaf, shut string, depth int) string {
		return strings.Repeat(open, depth) + leaf + strings.Repeat(shut, depth)
	}
	list := func(head, unit string, size int) []byte {
		n := max((size-len(head)-16)/(len(unit)+1), 1)
		return []byte(head + strings.TrimSuffix(strings.Repeat(unit+",", n), ",") + "]}")
	}
	var answer func(path string) []byte
	zipped := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := answer(r.URL.Path)
		if zipped {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(body)
			_ = zw.Close()
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	t.Setenv("BMC_PW", "hunter2")
	b := NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{{ID: "x11", URL: srv.URL, Username: "fairy",
		PasswordEnv: "BMC_PW", TLSFingerprint: hex.EncodeToString(sum[:])}}}, "")
	handle := func() (st int, out map[string]any, total uint64) {
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		st, out = b.Handle(context.Background(), BMCRequest{Target: "x11", Action: "status"})
		runtime.ReadMemStats(&m1)
		return st, out, m1.TotalAlloc - m0.TotalAlloc
	}

	// the honest BMC, with a list of systems and a system document of a real size (60 KiB)
	answer = func(path string) []byte {
		if path == "/redfish/v1/Systems" {
			return []byte(`{"@odata.id":"/redfish/v1/Systems","Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"Members@odata.count":1}`)
		}
		return bytes.Replace(list(system, `{"Name":"a sensor","Reading":12.1}`, 60<<10), []byte(`"On"`), []byte(`"Off"`), 1)
	}
	if st, out, _ := handle(); st != 200 || out["power"] != "off" {
		t.Fatalf("the honest BMC: %d %v", st, out)
	}

	for _, size := range []int{1 << 20, 256 << 10, 64 << 10} {
		for name, unit := range map[string]string{
			`flat {"":0}`:       `{"":0}`, // verifier V1: this shape killed the agent 4 times of 4
			`flat [{"":1}]`:     `[{"":1}]`,
			`nested objects 9k`: chain(`{"":`, "0", "}", 9000),
			`nested objects 20`: chain(`{"":`, "0", "}", 20),
			`deep arrays 9k`:    chain(`[`, "", "]", 9000),
		} {
			for _, where := range []string{"the list of systems", "the system"} {
				for _, zipped = range []bool{false, true} {
					answer = func(path string) []byte {
						switch {
						case path == "/redfish/v1/Systems" && where == "the list of systems":
							return list(systems, unit, size)
						case path == "/redfish/v1/Systems":
							return []byte(systems + "]}")
						}
						return list(system, unit, size)
					}
					st, out, total := handle()
					label := fmt.Sprintf("%s in %s, %d KiB, gzip %v", name, where, size>>10, zipped)
					if total > maxBMCRequestCost {
						t.Errorf("%s: allocated %d KiB (limit %d KiB)", label, total>>10, maxBMCRequestCost>>10)
					}
					if st == 200 {
						t.Errorf("%s: taken for a good answer: %v", label, out)
					}
				}
			}
		}
	}
}
