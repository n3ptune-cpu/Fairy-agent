package power

// Audit 4, T-02: what one answer of a configured power source may cost, for every source type that reads JSON
// over HTTP (tasmota, shelly Gen1 and Gen2, redfish / ipmi). The shapes are the ones of the auditors' and
// verifiers' proofs; the limits themselves are tested in pkg/devices.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// maxReadCost is what one Read of one source may allocate in all, whatever the device answers. Before the fix
// one answer of just under 4 MiB allocated up to 316 MiB.
const maxReadCost = 8 << 20

// The limits of pkg/devices on one JSON answer (maxJSONBody, maxJSONValues), repeated here to measure how much
// room the honest answers below leave.
const (
	limitBytes  = 256 << 10
	limitValues = 8192
)

// goodHead opens an answer that every source type reads as 5 W.
const goodHead = `{"apower":5,"StatusSNS":{"ENERGY":{"Power":5}},"meters":[{"power":5}],"PowerControl":[{"PowerConsumedWatts":5}],"x":[`

func chainOf(open, leaf, shut string, depth int) string {
	return strings.Repeat(open, depth) + leaf + strings.Repeat(shut, depth)
}

// hostileAnswers are JSON answers of just under size bytes that start with a good reading.
func hostileAnswers(size int) map[string][]byte {
	list := func(unit string) []byte {
		n := max((size-len(goodHead)-16)/(len(unit)+1), 1)
		return []byte(goodHead + strings.TrimSuffix(strings.Repeat(unit+",", n), ",") + "]}")
	}
	return map[string][]byte{
		`flat {"":0}`:       list(`{"":0}`),
		`flat [{"":1}]`:     list(`[{"":1}]`),
		`flat {}`:           list(`{}`),
		`flat 1`:            list(`1`),
		`nested objects 9k`: list(chainOf(`{"":`, "0", "}", 9000)),
		`nested objects 20`: list(chainOf(`{"":`, "0", "}", 20)),
		`deep arrays 9k`:    list(chainOf(`[`, "", "]", 9000)),
		`deep arrays 20`:    list(chainOf(`[`, "", "]", 20)),
	}
}

func gzipOf(t testing.TB, body []byte) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&zb, gzip.BestCompression)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zb.Bytes()
}

// device is a fake plug or BMC: it answers every request with *body, sent with gzip when *zipped is set.
type device struct {
	body   []byte
	zipped bool
}

func (d *device) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if d.zipped {
		w.Header().Set("Content-Encoding", "gzip")
	}
	_, _ = w.Write(d.body)
}

// jsonSources builds one source of every type that reads JSON over HTTP, all pointed at dev.
func jsonSources(t *testing.T, dev *device) map[string]Source {
	t.Helper()
	plain := httptest.NewServer(dev)
	t.Cleanup(plain.Close)
	bmc := httptest.NewTLSServer(dev)
	t.Cleanup(bmc.Close)
	t.Setenv("FAIRY_TEST_BMC_PASSWORD", "bmc-password")
	out := map[string]Source{}
	for name, cfg := range map[string]map[string]any{
		"tasmota":     {"id": "p", "type": "tasmota", "url": plain.URL},
		"shelly gen2": {"id": "p", "type": "shelly", "url": plain.URL, "gen": "2"},
		"shelly gen1": {"id": "p", "type": "shelly", "url": plain.URL, "gen": "1"},
		"shelly auto": {"id": "p", "type": "shelly", "url": plain.URL},
		"redfish":     {"id": "p", "type": "redfish", "url": bmc.URL, "password_env": "FAIRY_TEST_BMC_PASSWORD", "verify_tls": false},
		"ipmi":        {"id": "p", "type": "ipmi", "url": bmc.URL, "password_env": "FAIRY_TEST_BMC_PASSWORD", "verify_tls": false},
	} {
		s, err := Build(cfg, nil)
		if err != nil {
			t.Fatal(name, err)
		}
		t.Cleanup(s.Close)
		out[name] = s
	}
	return out
}

// readCost is what one Read allocated in all.
func readCost(s Source) (rs []Reading, err error, total uint64) {
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	rs, err = s.Read(context.Background(), 10*time.Second)
	runtime.ReadMemStats(&m1)
	return rs, err, m1.TotalAlloc - m0.TotalAlloc
}

func TestHostileDeviceAnswerCostsLittle(t *testing.T) {
	dev := &device{}
	sources := jsonSources(t, dev)
	for name, s := range sources { // one honest answer first: connections and TLS sessions are set up
		dev.body, dev.zipped = []byte(goodHead+"]}"), false
		if rs, err := s.Read(context.Background(), 10*time.Second); err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 5 {
			t.Fatalf("%s: the honest answer: %+v %v", name, rs, err)
		}
	}
	for _, size := range []int{4 << 20, 1 << 20, 256 << 10, 64 << 10} {
		for shape, body := range hostileAnswers(size) {
			zip := gzipOf(t, body)
			for _, zipped := range []bool{false, true} {
				dev.body, dev.zipped = body, zipped
				if zipped {
					dev.body = zip
				}
				for name, s := range sources {
					rs, err, total := readCost(s)
					label := fmt.Sprintf("%s: %s, %d KiB, gzip %v", name, shape, len(body)>>10, zipped)
					if total > maxReadCost {
						t.Errorf("%s: allocated %d KiB (limit %d KiB), err=%v", label, total>>10, maxReadCost>>10, err)
					}
					if err == nil || len(rs) != 0 {
						t.Errorf("%s: taken for a reading: %+v", label, rs)
					}
				}
			}
		}
	}
}

// The most expensive answer that passes the limits is read as a normal value and costs a fixed amount.
func TestWorstAcceptedDeviceAnswer(t *testing.T) {
	unit := chainOf(`{"":`, "0", "}", 30)
	body := []byte(goodHead + strings.TrimSuffix(strings.Repeat(unit+",", (limitValues-64)/31), ",") + "]}")
	body = append([]byte(`{"`+strings.Repeat("k", limitBytes-len(body)-64)+`":0,`), body[1:]...) // long keys cost memory too
	dev := &device{body: body}
	for name, s := range jsonSources(t, dev) {
		rs, err, total := readCost(s)
		if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 5 {
			t.Errorf("%s: %d bytes inside the limits were not read: %+v %v", name, len(body), rs, err)
		}
		if total > maxReadCost {
			t.Errorf("%s: allocated %d KiB (limit %d KiB)", name, total>>10, maxReadCost>>10)
		}
		t.Logf("%s: %d bytes, allocated %d KiB", name, len(body), total>>10)
	}
}

// Honest answers, as large as the supported devices send them, are read as before and use less than half of
// every limit. They are written by hand after the devices' documented answers, not recorded from devices: a
// Tasmota "Status 8" of a three-phase meter with extra sensors, the full /status of a Shelly 3EM, a Shelly
// Plus/Pro Switch.GetStatus and, for the BMC, a Redfish Power document with every property filled in for a
// large four-socket server (4 power supplies, 70 voltage sensors), indented with four spaces (most BMCs send
// it without indentation, at a third of the size). A document twice that large (8 supplies, 120 sensors) must
// still pass.
func TestLargeHonestAnswers(t *testing.T) {
	tasmota := `{"StatusSNS":{"Time":"2026-01-01T12:00:00","ANALOG":{"Temperature1":21.4,"A2":512},
		"ENERGY":{"TotalStartTime":"2024-03-01T08:00:00","Total":[1234.567,2345.678,3456.789],"Yesterday":[1.2,2.3,3.4],
		"Today":[0.5,0.6,0.7],"Period":[1,2,3],"Power":[95,100,105],"ApparentPower":[110,115,120],"ReactivePower":[20,21,22],
		"Factor":[0.86,0.87,0.88],"Frequency":[50,50,50],"Voltage":[230,231,229],"Current":[0.41,0.43,0.46]},
		"DS18B20-1":{"Id":"0316A279D2FF","Temperature":22.5},"DS18B20-2":{"Id":"0316A279D3FF","Temperature":19.1},
		"BME280":{"Temperature":21.9,"Humidity":40.2,"DewPoint":7.9,"Pressure":1012.4},"PressureUnit":"hPa","TempUnit":"C"}}`
	shellyGen1 := `{"wifi_sta":{"connected":true,"ssid":"home","ip":"192.168.1.50","rssi":-61},"cloud":{"enabled":false,"connected":false},
		"mqtt":{"connected":false},"time":"12:00","unixtime":1767268800,"serial":4242,"has_update":false,"mac":"AABBCCDDEEFF",
		"cfg_changed_cnt":3,"actions_stats":{"skipped":0},"relays":[{"ison":true,"has_timer":false,"timer_started":0,"timer_duration":0,
		"timer_remaining":0,"overpower":false,"is_valid":true,"source":"http"}],
		"emeters":[{"power":100.5,"pf":0.95,"current":0.46,"voltage":230.1,"is_valid":true,"total":250000.5,"total_returned":0.0},
		{"power":200.5,"pf":0.96,"current":0.91,"voltage":229.7,"is_valid":true,"total":350000.5,"total_returned":12.5},
		{"power":300.5,"pf":0.97,"current":1.35,"voltage":231.2,"is_valid":true,"total":450000.5,"total_returned":0.0}],
		"total_power":601.5,"emeter_n":{"current":0.02,"ixsum":2.72,"mismatch":false,"is_valid":true},"fs_mounted":true,"v_data":1,
		"ct_calst":0,"update":{"status":"idle","has_update":false,"new_version":"20230913-114244/v1.14.0-gcb84623",
		"old_version":"20230913-114244/v1.14.0-gcb84623","beta_version":"20231107-165007/v1.14.1-rc1-g0617c15"},
		"ram_total":49920,"ram_free":30260,"fs_size":233681,"fs_free":156624,"uptime":864000}`
	shellyGen2 := `{"id":0,"source":"init","output":true,"apower":95.5,"voltage":229.8,"freq":50.0,"current":0.41,"pf":0.98,
		"aenergy":{"total":12000.0,"by_minute":[1591.2,1590.8,1592.1],"minute_ts":1767268800},
		"ret_aenergy":{"total":0.0,"by_minute":[0.0,0.0,0.0],"minute_ts":1767268800},"temperature":{"tC":41.3,"tF":106.3}}`
	for name, c := range map[string]struct {
		body                 string
		source               string
		watts, volts, kwh    float64
		minBytes, minMembers int
	}{
		"tasmota, three phases": {tasmota, "tasmota", 300, 690, 7037.034, 600, 40},
		"shelly 3EM (Gen1)":     {shellyGen1, "shelly gen1", 100.5, 230.1, 250.0005, 1200, 70},
		"shelly Plus (Gen2)":    {shellyGen2, "shelly gen2", 95.5, 229.8, 12, 300, 20},
		"shelly Plus (auto)":    {shellyGen2, "shelly auto", 95.5, 229.8, 12, 300, 20},
		"BMC, large server":     {bigRedfishPower(4, 70), "redfish", 412, 232, 0, 60 << 10, 2000},
		"BMC, the same (ipmi)":  {bigRedfishPower(4, 70), "ipmi", 412, 232, 0, 60 << 10, 2000},
	} {
		dev := &device{body: []byte(c.body)}
		s := jsonSources(t, dev)[c.source]
		rs, err := s.Read(context.Background(), 10*time.Second)
		if err != nil || len(rs) != 1 {
			t.Errorf("%s: %+v %v", name, rs, err)
			continue
		}
		r := rs[0]
		near := func(p *float64, want float64) bool {
			return want == 0 || (p != nil && *p > want-0.01 && *p < want+0.01)
		}
		if !near(r.Watts, c.watts) || !near(r.Voltage, c.volts) || !near(r.EnergyKWhTotal, c.kwh) {
			t.Errorf("%s: read %s", name, mustJSON(r))
		}
		values := countValues(t, c.body)
		t.Logf("%s: %d bytes (limit %d), %d values (limit %d)", name, len(c.body), limitBytes, values, limitValues)
		if len(c.body) < c.minBytes || values < c.minMembers {
			t.Errorf("%s: the fixture shrank to %d bytes, %d values: it no longer stands for a large answer", name, len(c.body), values)
		}
		if 2*len(c.body) > limitBytes || 2*values > limitValues {
			t.Errorf("%s: an honest answer of %d bytes, %d values uses more than half of a limit (%d bytes, %d values)",
				name, len(c.body), values, limitBytes, limitValues)
		}
	}
	huge := bigRedfishPower(8, 120)
	rs, err := jsonSources(t, &device{body: []byte(huge)})["redfish"].Read(context.Background(), 10*time.Second)
	if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 412 {
		t.Errorf("a Power document of %d bytes, %d values was not read: %+v %v", len(huge), countValues(t, huge), rs, err)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// countValues counts the values of a JSON text the way pkg/devices does: one for the text, and one for every
// object, list and comma (an empty object or list counts as two).
func countValues(t *testing.T, body string) int {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any) int
	walk = func(v any) int {
		n := 1
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				n++
			}
			for _, e := range x {
				n += walk(e)
			}
		case []any:
			if len(x) == 0 {
				n++
			}
			for _, e := range x {
				n += walk(e)
			}
		}
		return n
	}
	return walk(v)
}

// bigRedfishPower is a Redfish Power document (schema Power.v1_5) with every property a BMC fills in, for a
// machine with this many power supplies and voltage sensors, indented.
func bigRedfishPower(supplies, voltages int) string {
	status := map[string]any{"Health": "OK", "HealthRollup": "OK", "State": "Enabled"}
	doc := map[string]any{
		"@odata.context": "/redfish/v1/$metadata#Power.Power", "@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power",
		"@odata.type": "#Power.v1_5_0.Power", "Id": "Power", "Name": "Power", "Description": "Power",
		"PowerControl@odata.count": 1, "PowerSupplies@odata.count": supplies, "Voltages@odata.count": voltages, "Redundancy@odata.count": 1,
		"PowerControl": []any{map[string]any{
			"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/PowerControl/0", "@odata.type": "#Power.v1_4_0.PowerControl",
			"MemberId": "PowerControl", "Name": "System Power Control", "PowerAllocatedWatts": 1100, "PowerAvailableWatts": 0,
			"PowerCapacityWatts": 1838, "PowerConsumedWatts": 412, "PowerRequestedWatts": 714,
			"PowerLimit":   map[string]any{"CorrectionInMs": 0, "LimitException": "HardPowerOff", "LimitInWatts": 714},
			"PowerMetrics": map[string]any{"AverageConsumedWatts": 405, "IntervalInMin": 60, "MaxConsumedWatts": 480, "MinConsumedWatts": 390},
			"RelatedItem": []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1"},
				map[string]any{"@odata.id": "/redfish/v1/Systems/System.Embedded.1"}},
			"RelatedItem@odata.count": 2, "Status": status,
			"Oem": map[string]any{"Dell": map[string]any{"HeadroomWatts": 688, "InstantaneousHeadroomWatts": 1426, "PeakHeadroomWatts": 1358}},
		}},
		"Redundancy": []any{map[string]any{
			"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/Redundancy/0", "@odata.type": "#Redundancy.v1_3_2.Redundancy",
			"MaxNumSupported": 4, "MemberId": "SystemBoardPSRedundancy", "MinNumNeeded": 2, "Mode": "N+m", "Name": "System Board PS Redundancy",
			"RedundancyEnabled": true, "RedundancySet@odata.count": supplies, "Status": status,
			"RedundancySet": []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/PowerSupplies/0"},
				map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/PowerSupplies/1"}},
		}},
	}
	var ps, vs []any
	for i := range supplies {
		ps = append(ps, map[string]any{
			"@odata.context": "/redfish/v1/$metadata#Power.Power", "@odata.type": "#Power.v1_5_3.PowerSupply",
			"@odata.id":         fmt.Sprintf("/redfish/v1/Chassis/System.Embedded.1/Power#/PowerSupplies/%d", i),
			"Assembly":          map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Assembly"},
			"EfficiencyPercent": 94, "FirmwareVersion": "00.1D.7D", "HotPluggable": true, "LastPowerOutputWatts": 206,
			"InputRanges": []any{map[string]any{"InputType": "AC", "MaximumFrequencyHz": 63, "MaximumVoltage": 264, "MinimumFrequencyHz": 47,
				"MinimumVoltage": 100, "OutputWattage": 1100}},
			"InputRanges@odata.count": 1, "LineInputVoltage": 232, "LineInputVoltageType": "AC240V", "Manufacturer": "DELL",
			"MemberId": fmt.Sprintf("PSU.Slot.%d", i+1), "Model": "PWR SPLY,1100W,RDNT,LTON", "Name": fmt.Sprintf("PS%d Status", i+1),
			"PartNumber": "0CMPGMA03", "PowerCapacityWatts": 1100, "PowerInputWatts": 220, "PowerOutputWatts": 206, "PowerSupplyType": "AC",
			"SerialNumber": "CNLOD0000000AA", "SparePartNumber": "0CMPGMA03", "Status": status,
			"Redundancy": []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/Redundancy/0",
				"@odata.type": "#Redundancy.v1_3_2.Redundancy", "MaxNumSupported": 4, "MemberId": "SystemBoardPSRedundancy", "MinNumNeeded": 2,
				"Mode": "N+m", "Name": "System Board PS Redundancy", "RedundancyEnabled": true, "Status": status,
				"RedundancySet": []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power#/PowerSupplies/0"}}}},
			"Redundancy@odata.count":  1,
			"RelatedItem":             []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1"}},
			"RelatedItem@odata.count": 1,
			"Oem": map[string]any{"Dell": map[string]any{
				"DellPowerSupply": map[string]any{"@odata.type": "#DellPowerSupply.v1_1_0.DellPowerSupply", "ActiveInputVoltage": "240V",
					"IsSwitchingSupply": true, "OperationalStatus": []any{"OK"}, "RequestedState": "NotApplicable"},
				"DellPowerSupplyView": map[string]any{"@odata.type": "#DellPowerSupplyView.v1_3_0.DellPowerSupplyView", "DetailedState": "Presence Detected",
					"DeviceDescription": fmt.Sprintf("Power Supply %d", i+1), "LastSystemInventoryTime": "2026-01-01T12:00:00+00:00",
					"LastUpdateTime": "2026-01-01T12:00:00+00:00", "PMBusMonitoring": "Capable", "Range1MaxInputPowerWatts": 1260,
					"RedMinNumberNeeded": 2, "RedTypeOfSet": "N+1, Sparing", "RedundancyStatus": "Redundant"}}},
		})
	}
	for i := range voltages {
		vs = append(vs, map[string]any{
			"@odata.context": "/redfish/v1/$metadata#Power.Power", "@odata.type": "#Power.v1_3_0.Voltage",
			"@odata.id":              fmt.Sprintf("/redfish/v1/Chassis/System.Embedded.1/Power#/Voltages/%d", i),
			"LowerThresholdCritical": 10.8, "LowerThresholdFatal": 10.2, "LowerThresholdNonCritical": 11.2, "MaxReadingRange": 15.3,
			"MemberId":        fmt.Sprintf("iDRAC.Embedded.1#SystemBoard%dVPG", i),
			"MinReadingRange": 0, "Name": fmt.Sprintf("System Board VCCIO %d PG", i), "PhysicalContext": "SystemBoard",
			"ReadingVolts": 12.1, "SensorNumber": 35 + i, "Status": status, "UpperThresholdCritical": 13.2,
			"UpperThresholdFatal": 13.8, "UpperThresholdNonCritical": 12.8,
			"RelatedItem":             []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1"}},
			"RelatedItem@odata.count": 1,
		})
	}
	doc["PowerSupplies"], doc["Voltages"] = ps, vs
	b, _ := json.MarshalIndent(doc, "", "    ")
	return string(b)
}
