package agent

// Audit 4, T-60: `fairy-agent fans-auto` read env_file (plug passwords, UPS passwords, BMC passwords) into its
// environment and started ipmitool with all of it. The running agent hides these names from every program it
// starts; the new command did not.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
)

func TestFansAutoHidesDeviceSecretsFromItsChild(t *testing.T) {
	inFile := []string{"T60_PLUG_PASSWORD", "T60_UPS_PASSWORD", "T60_OTHER_BMC_PW"}
	for _, n := range inFile { // not set before: env_file sets them; the test's end removes them again
		t.Setenv(n, "x")
		os.Unsetenv(n)
	}
	t.Setenv("T60_RELAY_PW", "dummy-relay") // a BMC relay target's password, set outside env_file
	t.Setenv("T60_IPMI_PW", "dummy-ipmi")   // ipmi.password_env, the same
	t.Setenv("T60_NOT_A_SECRET", "stays")   // any other variable is passed on as before
	dir := t.TempDir()
	envFile := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(envFile, []byte("T60_PLUG_PASSWORD=dummy1\nT60_UPS_PASSWORD=dummy2\nT60_OTHER_BMC_PW=dummy3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mustParse(t, "ipmi: {enabled: true, password_env: T60_IPMI_PW}\nfan_control: {enabled: true}\nenv_file: "+envFile+"\n"+
		"bmc_relay: {enabled: true, targets: [{id: x, host: 192.168.1.5, username: u, password_env: T60_RELAY_PW}]}\n")

	// The real transport gives ipmitool collect.MinimalEnv() as its environment, taken when it is built
	// (IPMITransport). This stand-in takes it at the same moment.
	var child []string
	old := ipmiTransport
	t.Cleanup(func() { ipmiTransport = old })
	bmc := fakebmc.X11SCAF()
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	ipmiTransport = func(IPMIConfig) (ipmi.Transport, error) {
		child = collect.MinimalEnv()
		return bmc, nil
	}
	if mode, done, err := FansAuto(context.Background(), cfg); err != nil || !done || mode != "optimal" {
		t.Fatal(mode, done, err)
	}
	for _, n := range inFile {
		if os.Getenv(n) == "" {
			t.Fatalf("env_file was not read: %s is not set", n)
		}
	}
	seen := map[string]bool{}
	for _, kv := range child {
		k, _, _ := strings.Cut(kv, "=")
		seen[strings.ToUpper(k)] = true
	}
	for _, n := range append(inFile, "T60_RELAY_PW", "T60_IPMI_PW") {
		if seen[n] {
			t.Errorf("the ipmitool child of fans-auto would get %s", n)
		}
	}
	if !seen["T60_NOT_A_SECRET"] {
		t.Error("a variable that is no secret was not passed on: the test's stand-in does not see the environment")
	}
}
