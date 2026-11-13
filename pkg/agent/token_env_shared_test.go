package agent

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Second review of ha1: what the variable named by token_env holds is sent to Home Assistant with every
// reading. An entry whose token_env names the variable that a plug, a UPS, the BMC or a BMC relay target keeps
// its password in would send that password there. Such a config is refused where the relay is built (the
// agent's start, check-config), with fixed words that name the two settings by id and never the variable.
func TestTokenEnvIsNotAVariableAnotherSettingNames(t *testing.T) {
	const ha = `  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_SHARED, entity: sensor.desk_plug_power}` + "\n"
	const words = ": what that variable holds would be sent to Home Assistant as the token. The token needs a variable that nothing else names"
	relay := func(t *testing.T, conf string) error {
		t.Helper()
		cfg, err := Parse([]byte(conf), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewRelay(cfg.PowerSources, cfg.UPS); err != nil { // each entry for itself is in order
			t.Fatal(err)
		}
		r, err := cfg.NewRelay()
		if (r == nil) != (err != nil) {
			t.Fatalf("relay %v, error %v", r, err)
		}
		return err
	}

	bad := map[string]struct{ conf, want string }{
		"a Shelly plug's password": {"power_sources:\n" + ha +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHARED}` + "\n",
			"password_env of power source shelly-1"},
		"a plug before the entry": {"power_sources:\n" +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHARED}` + "\n" + ha,
			"password_env of power source shelly-1"},
		"a Tasmota plug's, in small letters": {"power_sources:\n" + ha +
			`  - {id: tasmota-1, type: tasmota, url: "http://192.0.2.12", password_env: tes_shared}` + "\n",
			"password_env of power source tasmota-1"},
		"a BMC's (redfish)": {"power_sources:\n" + ha +
			`  - {id: bmc-1, type: redfish, url: "https://192.0.2.13", username: u, password_env: TES_SHARED}` + "\n",
			"password_env of power source bmc-1"},
		"a UPS's among the power sources": {"power_sources:\n" + ha +
			`  - {id: nut-1, type: nut, host: 192.0.2.14, ups: rack, username: u, password_env: Tes_Shared}` + "\n",
			"password_env of power source nut-1"},
		"a ups entry's": {"power_sources:\n" + ha + "ups:\n" +
			`  - {id: rack, host: 192.0.2.71, username: monuser, password_env: TES_SHARED}` + "\n",
			"password_env of ups rack"},
		"the BMC's": {"power_sources:\n" + ha +
			"ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: TES_SHARED}\n",
			"ipmi.password_env"},
		"a BMC relay target's": {"power_sources:\n" + ha +
			"bmc_relay: {enabled: true, targets: [{id: a, host: 192.168.1.6, username: u, password_env: TES_OTHER}, " +
			"{id: server-bmc, host: 192.168.1.7, username: u, password_env: TES_SHARED}]}\n",
			"password_env of bmc_relay target server-bmc"},
		"the second homeassistant entry": {"power_sources:\n" +
			`  - {id: rack-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_HA, entity: sensor.rack_plug_power}` + "\n" + ha +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHARED}` + "\n",
			"password_env of power source shelly-1"},
	}
	for name, c := range bad {
		err := relay(t, c.conf)
		if want := "power source desk-plug: token_env names the same variable as " + c.want + words; err == nil || err.Error() != want {
			t.Errorf("%s: %v\nwant %s", name, err, want)
		}
		if err != nil && strings.Contains(strings.ToUpper(err.Error()), "TES_") {
			t.Errorf("%s: the error names the variable: %v", name, err)
		}
	}

	good := map[string]string{
		"a variable of its own": "power_sources:\n" + ha +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHELLY}` + "\n" +
			"ups:\n" + `  - {id: rack, host: 192.0.2.71, username: monuser, password_env: TES_UPS}` + "\n" +
			"ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: TES_IPMI}\n" +
			"bmc_relay: {enabled: true, targets: [{id: a, host: 192.168.1.6, username: u, password_env: TES_RELAY}]}\n",
		"two plugs of one Home Assistant share its token": "power_sources:\n" + ha +
			`  - {id: rack-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_SHARED, entity: sensor.rack_plug_power}` + "\n",
		"a longer and a shorter name": "power_sources:\n" + ha +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHARED_2}` + "\n" +
			`  - {id: shelly-2, type: shelly, url: "http://192.0.2.12", password_env: TES_SHARE}` + "\n",
		"the name as another member's value": "power_sources:\n" + ha +
			`  - {id: shelly-1, type: shelly, name: TES_SHARED, url: "http://192.0.2.11", password_env: TES_SHELLY}` + "\n",
		"an ignored entry named it (its note says to leave the line)": "power_sources:\n" + ha +
			`  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: TES_SHARED}` + "\n",
		"plugs that share a password with each other, as before": "power_sources:\n" +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHELLY}` + "\n" +
			`  - {id: shelly-2, type: shelly, url: "http://192.0.2.12", password_env: TES_SHELLY}` + "\n" +
			"ups:\n" + `  - {id: rack, host: 192.0.2.71, username: monuser, password_env: TES_SHELLY}` + "\n",
		"no power sources at all": "ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: TES_IPMI}\n",
	}
	for name, conf := range good {
		if err := relay(t, conf); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The agent does not start with such a config: Run returns the error before it listens.
func TestRunRefusesATokenEnvAnotherSettingNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Run looks for the helper service on Windows")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", strings.Repeat("r", 12)+"0123456789abcdefghij")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	cfg := mustParse(t, "listen: "+freeAddr(t)+"\npower_sources:\n"+
		`  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_RUN_SHARED, entity: sensor.desk_plug_power}`+"\n"+
		`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_RUN_SHARED}`+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, Build{Version: "test"}) }()
	select {
	case err := <-done:
		if err == nil || !strings.HasPrefix(err.Error(), "power source desk-plug: token_env names the same variable as password_env of power source shelly-1: ") {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run started with a token_env that a plug names for its password")
	}
}
