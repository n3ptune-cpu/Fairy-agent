package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIpmitool is ipmitool as the test binary plays it (TestMain, FAKE_IPMITOOL_MODE): it checks that the
// password arrived only in IPMI_PASSWORD and answers like ipmitool does.
func fakeIpmitool(mode string, args []string) int {
	line := strings.Join(args, " ")
	if strings.Contains(line, "hunter2") || os.Getenv("IPMI_PASSWORD") != "hunter2" || !strings.Contains(line, "-E") {
		fmt.Println("password not passed as expected:", line)
		return 9
	}
	if os.Getenv("FAIRY_AGENT_TOKEN") != "" {
		fmt.Println("the agent's own secrets leaked into ipmitool's environment")
		return 9
	}
	_ = os.WriteFile(os.Getenv("FAKE_IPMITOOL_ARGS"), []byte(line), 0o600)
	switch mode {
	case "ok":
		if strings.HasSuffix(line, "chassis power on") {
			fmt.Println("Chassis Power Control: Up/On")
		} else {
			fmt.Println("Chassis Power is off")
		}
		return 0
	case "badpass":
		fmt.Fprintln(os.Stderr, "Error: Unable to establish IPMI v2 / RMCP+ session\\nRAKP 2 HMAC is invalid")
		return 1
	case "down":
		fmt.Fprintln(os.Stderr, "Error: Unable to establish IPMI v2 / RMCP+ session")
		return 1
	case "role":
		fmt.Fprintln(os.Stderr, "IANA PEN registry open failed: No such file or directory")
		fmt.Fprintln(os.Stderr, "Error in open session response message : invalid role")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Error: Unable to establish IPMI v2 / RMCP+ session")
		return 1
	}
	return 2
}

const bmcCfg = `bmc_relay:
  enabled: true
  targets:
    - {id: cyrene-bmc, backend: ipmitool, host: 192.168.254.254, username: fairy, password_env: BMC_CYRENE_PASSWORD, cipher_suite: 17}
control_rate_per_min: 30
`

func TestBMCRelayIpmitool(t *testing.T) {
	args := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKE_IPMITOOL_ARGS", args)
	t.Setenv("BMC_CYRENE_PASSWORD", "hunter2")
	t.Setenv("FAIRY_AGENT_TOKEN", "must-not-leak")
	r := newRig(t, bmcCfg)
	_, m := r.do(t, "GET", "/metrics", readTok, nil)
	if f := m["features"].(map[string]any); f["bmc_relay"] != true {
		t.Fatal(f)
	}
	if b := fmt.Sprint(m["bmc_relay"]); !strings.Contains(b, "cyrene-bmc") || strings.Contains(b, "192.168") || strings.Contains(b, "fairy") {
		t.Fatal("metrics must list target ids only", b)
	}
	if st, _ := r.do(t, "POST", "/bmc/power", readTok, map[string]any{"target": "cyrene-bmc", "action": "on"}); st != 401 {
		t.Fatal("read token", st)
	}
	t.Setenv("FAKE_IPMITOOL_MODE", "ok")
	st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "on", "requested_by": "neptune"})
	if st != 200 || b["power"] != "on" || b["backend"] != "ipmitool" {
		t.Fatal(st, b)
	}
	got, _ := os.ReadFile(args)
	if string(got) != "-I lanplus -H 192.168.254.254 -U fairy -E -C 17 chassis power on" {
		t.Fatal(string(got))
	}
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "status"}); st != 200 || b["power"] != "off" {
		t.Fatal(st, b)
	}
	t.Setenv("FAKE_IPMITOOL_MODE", "badpass")
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "on"}); st != 502 || b["code"] != "bmc_refused" {
		t.Fatal(st, b)
	}
	t.Setenv("FAKE_IPMITOOL_MODE", "down")
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "on"}); st != 502 || b["code"] != "bmc_unreachable" ||
		!strings.Contains(b["error"].(string), "cabled") {
		t.Fatal(st, b)
	}
	t.Setenv("FAKE_IPMITOOL_MODE", "role") // was reported as "not reachable (is the relay cabled to it?)"
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "on"}); st != 502 || b["code"] != "bmc_privilege" ||
		strings.Contains(b["error"].(string), "cabled") || strings.Contains(b["error"].(string), "IANA") || !strings.Contains(b["error"].(string), "Administrator") {
		t.Fatal(st, b)
	}
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "nope", "action": "on"}); st != 404 || b["code"] != "unknown_target" {
		t.Fatal(st, b)
	}
	if st, _ := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "off"}); st != 400 {
		t.Fatal("only on / status", st)
	}
	t.Setenv("BMC_CYRENE_PASSWORD", "")
	if st, b := r.do(t, "POST", "/bmc/power", ctlTok, map[string]any{"target": "cyrene-bmc", "action": "on"}); st != 409 || b["code"] != "bmc_password_missing" {
		t.Fatal(st, b)
	}
}

func TestBMCRelayConfigChecks(t *testing.T) {
	for y, want := range map[string]string{
		"bmc_relay: {enabled: true}": "at least one",
		"bmc_relay: {targets: [{id: x, host: 8.8.8.8, username: u, password_env: P}]}":                                   "private IP",
		"bmc_relay: {targets: [{id: x, host: 10.0.0.5, username: u, password_env: P, cipher_suite: 18}]}":                "0-17",
		"bmc_relay: {targets: [{id: x, url: \"http://10.0.0.5\", username: u, password_env: P}]}":                        "https://",
		"bmc_relay: {targets: [{id: x, url: \"https://bmc.example.com\", username: u, password_env: P}]}":                "https://",
		"bmc_relay: {targets: [{id: x, url: \"https://10.0.0.5\", username: u, password_env: P, tls_fingerprint: abc}]}": "SHA-256",
		"bmc_relay: {targets: [{id: X!, host: 10.0.0.5, username: u, password_env: P}]}":                                 ".id",
		"bmc_relay: {targets: [{id: x, host: 10.0.0.5, password_env: P}]}":                                               "username",
		"bmc_relay: {targets: [{id: x, host: 10.0.0.5, username: u, password_env: \"no way\"}]}":                         "password_env",
		"bmc_relay: {targets: [{id: x, host: 10.0.0.5, username: u, password_env: P, backend: ssh}]}":                    "backend",
		"bmc_relay: {targets: [{id: x, host: 10.0.0.5, username: u, password_env: P, ipmitool_path: ipmitool}]}":         "absolute",
	} {
		if _, err := Parse([]byte(y), "/etc/fairy-agent/config.yaml"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", y, err)
		}
	}
	c, err := Parse([]byte(bmcCfg), "/etc/fairy-agent/config.yaml")
	if err != nil || !c.ControlEnabled() || c.BMCRelay.Targets[0].EffectiveBackend() != "ipmitool" {
		t.Fatal(err)
	}
	if (BMCTarget{URL: "https://10.0.0.5"}).EffectiveBackend() != "redfish" || (BMCTarget{Host: "10.0.0.5"}).EffectiveBackend() != "ipmitool" {
		t.Fatal("default backend")
	}
}

// Redfish against a fake BMC (TLS, self-signed): the certificate is learned on first use and pinned after.
func TestBMCRelayRedfish(t *testing.T) {
	var resets []string
	power := "Off"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "fairy" || p != "hunter2" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/redfish/v1/Systems":
			_ = json.NewEncoder(w).Encode(map[string]any{"Members": []any{map[string]any{"@odata.id": "/redfish/v1/Systems/1"}}})
		case r.Method == "GET" && r.URL.Path == "/redfish/v1/Systems/1":
			_ = json.NewEncoder(w).Encode(map[string]any{"PowerState": power})
		case r.Method == "POST" && r.URL.Path == "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			resets = append(resets, fmt.Sprint(b["ResetType"]))
			power = "On"
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	t.Setenv("BMC_PW", "hunter2")
	pins := filepath.Join(t.TempDir(), "bmc-pins.json")
	b := NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{{ID: "x11", URL: srv.URL, Username: "fairy", PasswordEnv: "BMC_PW"}}}, pins)
	ctx := context.Background()
	if st, out := b.Handle(ctx, BMCRequest{Target: "x11", Action: "status"}); st != 200 || out["power"] != "off" {
		t.Fatal(st, out)
	}
	if saved, _ := os.ReadFile(pins); !strings.Contains(string(saved), fp) {
		t.Fatal("not pinned", string(saved))
	}
	if st, out := b.Handle(ctx, BMCRequest{Target: "x11", Action: "on"}); st != 200 || out["power"] != "on" || strings.Join(resets, ",") != "On" {
		t.Fatal(st, out, resets)
	}
	// a different certificate later: refused
	b2 := NewBMCRelay(BMCRelayConfig{Targets: []BMCTarget{{ID: "x11", URL: srv.URL, Username: "fairy", PasswordEnv: "BMC_PW",
		TLSFingerprint: strings.Repeat("ab", 32)}}}, "")
	if st, out := b2.Handle(ctx, BMCRequest{Target: "x11", Action: "on"}); st != 502 || out["code"] != "bmc_certificate_changed" {
		t.Fatal(st, out)
	}
	// configured fingerprint with colons and upper case works
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, strings.ToUpper(fp[i:i+2]))
	}
	b3 := NewBMCRelay(BMCRelayConfig{Targets: []BMCTarget{{ID: "x11", URL: srv.URL, Username: "fairy", PasswordEnv: "BMC_PW",
		TLSFingerprint: strings.Join(colons, ":")}}}, "")
	if st, out := b3.Handle(ctx, BMCRequest{Target: "x11", Action: "status"}); st != 200 || out["power"] != "on" {
		t.Fatal(st, out)
	}
	t.Setenv("BMC_PW", "wrong")
	if st, out := b3.Handle(ctx, BMCRequest{Target: "x11", Action: "on"}); st != 502 || out["code"] != "bmc_refused" {
		t.Fatal(st, out)
	}
	// nothing listening: unreachable
	srv.Close()
	t.Setenv("BMC_PW", "hunter2")
	if st, out := b3.Handle(ctx, BMCRequest{Target: "x11", Action: "on"}); st != 502 || out["code"] != "bmc_unreachable" {
		t.Fatal(st, out)
	}
}

// ipmitool's messages as real BMCs produce them (lanplus): the line before "Unable to establish IPMI v2 / RMCP+
// session" decides; the IANA PEN warning is noise.
func TestClassifyIpmitool(t *testing.T) {
	cs := 17
	tg := BMCTarget{ID: "x", Host: "192.168.254.254", Username: "fairy", PasswordEnv: "BMC_PW", CipherSuite: &cs}
	pen := "IANA PEN registry open failed: No such file or directory\n"
	for out, code := range map[string]string{
		pen + "Error in open session response message : invalid role\nError: Unable to establish IPMI v2 / RMCP+ session":                                      "bmc_privilege",
		"Set Session Privilege Level to ADMINISTRATOR failed: Insufficient privilege level\nError: Unable to establish IPMI v2 / RMCP+ session":                "bmc_privilege",
		"RAKP 2 message indicates an error : unauthorized role or privilege level requested":                                                                   "bmc_privilege",
		"Error in open session response message : no cipher suite match with proposed security algorithms\nError: Unable to establish IPMI v2 / RMCP+ session": "bmc_cipher",
		"Unsupported cipher suite ID : 18":                                                                                      "bmc_cipher",
		"Error in open session response message : invalid integrity algorithm":                                                  "bmc_cipher",
		"RAKP 2 message indicates an error : unauthorized name\nError: Unable to establish IPMI v2 / RMCP+ session":             "bmc_refused",
		pen + "RAKP 2 HMAC is invalid\nError: Unable to establish IPMI v2 / RMCP+ session":                                      "bmc_refused",
		"Error in open session response message : insufficient resources to create a session":                                   "bmc_busy",
		"RAKP 4 message indicates an error : invalid session ID in request\nError: Unable to establish IPMI v2 / RMCP+ session": "bmc_session",
		pen + "Error: Unable to establish IPMI v2 / RMCP+ session":                                                              "bmc_unreachable",
		"Address lookup for 192.168.254.254 failed":                                                                             "bmc_unreachable",
		"Error: something new": "bmc_error",
	} {
		err := classifyIpmitool(tg, cleanIpmitoolOutput(out, "hunter2"))
		var be *bmcError
		if !errors.As(err, &be) || be.code != code {
			t.Errorf("%q: got %v, want %s", out, err, code)
			continue
		}
		if strings.Contains(be.msg, "IANA") {
			t.Errorf("%q: the PEN warning was kept: %s", out, be.msg)
		}
		if code != "bmc_unreachable" && strings.Contains(be.msg, "cabled") {
			t.Errorf("%q: blamed the cable: %s", out, be.msg)
		}
	}
	if got := cleanIpmitoolOutput("IANA PEN registry open failed: No such file or directory\r\nChassis Power is on\r\n", ""); got != "Chassis Power is on" {
		t.Fatal(got)
	}
	if got := cleanIpmitoolOutput("Error: password hunter2 rejected", "hunter2"); strings.Contains(got, "hunter2") {
		t.Fatal(got)
	}
}
