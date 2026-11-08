package collect

// The `battery` block of /metrics (laptops; left out on machines without a system battery).
//
// Linux: /sys/class/power_supply. Batteries (type Battery, not scope Device such as a mouse) report either
// energy_* (µWh) or charge_* (µAh, converted with voltage_min_design or voltage_now), power_now (µW) or
// current_now (µA) x voltage_now (µV), capacity (%), status. AC: any power supply of type Mains or USB (USB-C
// chargers) with online = 1. Several batteries (some ThinkPads) are added up.
//
// Windows: GetSystemPowerStatus (percent, AC, Windows' own time estimate); no rate, which would need the
// battery driver's IOCTLs.

import (
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// BatteryStatus is the `battery` block. PowerW is positive while discharging (the draw of the whole machine
// then) and negative while charging; nil when unknown.
type BatteryStatus struct {
	Percent        *float64 `json:"percent"`
	State          string   `json:"state"` // charging | discharging | full | idle
	ACOnline       *bool    `json:"ac_online"`
	PowerW         *float64 `json:"power_w"`
	TimeRemainingS *int64   `json:"time_remaining_s"` // to empty while discharging, to full while charging
	HealthPct      *float64 `json:"health_pct"`       // full capacity now / design capacity
}

// BatteryStateOf maps a power_supply status to the /metrics state ("" for an unknown status).
func BatteryStateOf(status string, ac *bool) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "charging":
		return "charging"
	case "discharging":
		return "discharging"
	case "full":
		return "full"
	case "not charging":
		return "idle"
	}
	if ac != nil {
		if *ac {
			return "idle"
		}
		return "discharging"
	}
	return ""
}

// ReadBatteryStatus reads the system batteries and AC adapters under sysRoot (/sys); nil without a battery.
func ReadBatteryStatus(sysRoot string) *BatteryStatus {
	dirs, _ := filepath.Glob(filepath.Join(sysRoot, "class", "power_supply", "*"))
	sort.Strings(dirs)
	var ac *bool
	type bat struct {
		status                     string
		capacity                   float64
		hasCap                     bool
		now, full, design, watts   float64
		hasNow, hasFull, hasDesign bool
		hasWatts                   bool
		toEmpty, toFull            float64
		hasToEmpty, hasToFull      bool
	}
	var bats []bat
	for _, d := range dirs {
		typ, _ := readTrim(filepath.Join(d, "type"))
		if s, _ := readTrim(filepath.Join(d, "scope")); s == "Device" {
			continue
		}
		switch typ {
		case "Mains", "USB":
			if v, ok := readNum(filepath.Join(d, "online")); ok {
				on := v == 1
				if ac == nil || on {
					ac = &on
				}
			}
			continue
		case "Battery":
		default:
			continue
		}
		if v, ok := readNum(filepath.Join(d, "present")); ok && v == 0 {
			continue
		}
		var b bat
		b.status, _ = readTrim(filepath.Join(d, "status"))
		num := func(name string) (float64, bool) {
			v, ok := readNum(filepath.Join(d, name))
			return v, ok && !math.IsNaN(v) && !math.IsInf(v, 0)
		}
		b.capacity, b.hasCap = num("capacity")
		volts, okV := num("voltage_min_design")
		if !okV || volts <= 0 {
			volts, okV = num("voltage_now")
		}
		energy := func(kind string) (float64, bool) { // µWh
			if v, ok := num("energy_" + kind); ok {
				return v, true
			}
			if v, ok := num("charge_" + kind); ok && okV && volts > 0 {
				return v * volts / 1e6, true // µAh x µV = 1e-12 Wh; /1e6 gives µWh
			}
			return 0, false
		}
		b.now, b.hasNow = energy("now")
		b.full, b.hasFull = energy("full")
		b.design, b.hasDesign = energy("full_design")
		if p, ok := num("power_now"); ok {
			b.watts, b.hasWatts = math.Abs(p)/1e6, true
		} else if c, ok := num("current_now"); ok {
			if v, ok := num("voltage_now"); ok {
				b.watts, b.hasWatts = math.Abs(c*v)/1e12, true
			}
		}
		b.toEmpty, b.hasToEmpty = num("time_to_empty_now")
		b.toFull, b.hasToFull = num("time_to_full_now")
		bats = append(bats, b)
	}
	if len(bats) == 0 {
		return nil
	}
	out := &BatteryStatus{ACOnline: ac}
	var now, full, design, watts, capSum float64
	allEnergy, allDesign, anyWatts, nCap := true, true, false, 0
	states := map[string]bool{}
	for _, b := range bats {
		allEnergy = allEnergy && b.hasNow && b.hasFull && b.full > 0
		allDesign = allDesign && b.hasFull && b.hasDesign && b.design > 0
		now, full, design = now+b.now, full+b.full, design+b.design
		if b.hasWatts {
			watts += b.watts
			anyWatts = true
		}
		if b.hasCap {
			capSum += b.capacity
			nCap++
		}
		if s := BatteryStateOf(b.status, ac); s != "" {
			states[s] = true
		}
	}
	switch {
	case allEnergy:
		out.Percent = P(Round(math.Min(100, 100*now/full), 1))
	case nCap > 0:
		out.Percent = P(Round(math.Max(0, math.Min(100, capSum/float64(nCap))), 1))
	}
	// one battery charging or discharging decides; otherwise full only if all are full
	switch {
	case states["discharging"]:
		out.State = "discharging"
	case states["charging"]:
		out.State = "charging"
	case states["idle"]:
		out.State = "idle"
	case states["full"]:
		out.State = "full"
	case ac != nil && !*ac:
		out.State = "discharging"
	default:
		out.State = "idle"
	}
	if allDesign && design > 0 {
		out.HealthPct = P(Round(math.Min(150, 100*full/design), 1))
	}
	if anyWatts && watts < 1000 {
		switch out.State {
		case "discharging":
			out.PowerW = P(Round(watts, 1))
		case "charging":
			out.PowerW = P(-Round(watts, 1))
		default:
			out.PowerW = P(0.0)
		}
	}
	var secs float64
	switch {
	case out.State == "discharging" && len(bats) == 1 && bats[0].hasToEmpty && bats[0].toEmpty > 0:
		secs = bats[0].toEmpty
	case out.State == "charging" && len(bats) == 1 && bats[0].hasToFull && bats[0].toFull > 0:
		secs = bats[0].toFull
	case out.State == "discharging" && allEnergy && anyWatts && watts > 0.1:
		secs = now / 1e6 / watts * 3600
	case out.State == "charging" && allEnergy && anyWatts && watts > 0.1 && full > now:
		secs = (full - now) / 1e6 / watts * 3600
	}
	if secs > 0 && secs < 7*86400 {
		out.TimeRemainingS = P(int64(secs))
	}
	return out
}

// WindowsBattery builds the block from GetSystemPowerStatus's fields; nil without a system battery.
func WindowsBattery(acLine, flag, percent byte, lifeTime uint32) *BatteryStatus {
	if flag == 128 || flag == 255 { // no system battery / status unknown
		return nil
	}
	out := &BatteryStatus{}
	if acLine <= 1 {
		out.ACOnline = P(acLine == 1)
	}
	if percent <= 100 {
		out.Percent = P(float64(percent))
	}
	switch {
	case flag&8 != 0:
		out.State = "charging"
	case acLine == 1 && percent >= 100 && percent != 255:
		out.State = "full"
	case acLine == 1:
		out.State = "idle"
	default:
		out.State = "discharging"
	}
	if out.State == "discharging" && lifeTime != 0xFFFFFFFF && lifeTime > 0 && lifeTime < 7*86400 {
		out.TimeRemainingS = P(int64(lifeTime))
	}
	return out
}
