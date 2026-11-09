package collect

// Radeon temperature and power on Windows from AMD's own user-mode library, ADL (atiadlxx.dll, which the
// Adrenalin driver installs; atiadlxy.dll as a fallback). Read only: only ...Get / Query functions are called,
// never a Set or any Overdrive write; no driver of our own and nothing read from other processes. Per card, by
// what the card's Overdrive version offers:
//
//	8 (Navi and newer, e.g. RX 5600 XT): ADL2_New_QueryPMLogData_Get -> PMLog sensors: edge temperature (8, else
//	  hotspot 27) in °C, board power (73, newer drivers) else ASIC power (23) in W
//	7 (OverdriveN, Polaris / Vega): ADL2_OverdriveN_Temperature_Get (edge, m°C), ADL2_Overdrive6_CurrentPower_Get
//	6: ADL2_Overdrive6_Temperature_Get (m°C), ADL2_Overdrive6_CurrentPower_Get (total, 1/256 W)
//	5: ADL2_Overdrive5_Temperature_Get (m°C)
//
// ADL lists one "adapter" per display output; they are grouped by PCI location, which is also how they are
// matched to the cards found through DXGI (wingpu.go). This file holds the platform-independent part, over the
// ADLLib interface (the DLL on Windows, a fake in tests).

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"
)

// ADLAdapter is one ADL adapter (AdapterInfo).
type ADLAdapter struct {
	Index                 int
	Bus, Device, Function int
	VendorID              int
	Name                  string
	Present, Exist        bool
}

// ADLSensor is one PMLog sensor (ADLSingleSensorData).
type ADLSensor struct {
	Supported bool
	Value     int32
}

// PMLog sensor numbers (ADL_PMLOG_SENSORS in adl_defines.h).
const (
	pmlogTempEdge    = 8
	pmlogASICPower   = 23
	pmlogTempHotspot = 27
	pmlogBoardPower  = 73
)

// ADLLib is the ADL calls the agent uses. Every method only reads.
type ADLLib interface {
	Adapters() ([]ADLAdapter, error)
	OverdriveVersion(index int) (int, error) // ADL2_Overdrive_Caps
	PMLog(index int) ([]ADLSensor, error)    // ADL2_New_QueryPMLogData_Get (OD8)
	ODNTemperature(index int) (int, error)   // m°C
	OD6Temperature(index int) (int, error)   // m°C
	OD6Power(index int) (int, error)         // 1/256 W
	OD5Temperature(index int) (int, error)   // m°C
}

// AMDReading is what ADL says about one card.
type AMDReading struct {
	TempC, PowerW *float64
}

type adlCard struct {
	index   int
	version int
	loc     PCILoc
	name    string
	warned  bool
}

// AMDSensors reads Radeon temperature / power through ADL and attaches them to the matching GPUs.
type AMDSensors struct {
	lib   ADLLib
	mu    sync.Mutex
	cards []*adlCard
}

// NewAMDSensors lists the AMD cards ADL knows (one entry per PCI location); nil when there is none or ADL fails.
// It logs one line saying what ADL answered (ADLDiagnosis): when a Radeon gets no temperature, that line tells
// why.
func NewAMDSensors(lib ADLLib) *AMDSensors {
	if lib == nil {
		return nil
	}
	diag := ADLDiagnosis{}
	if d, ok := lib.(interface{ Opened() string }); ok {
		diag.Opened = d.Opened()
	}
	ads, err := lib.Adapters()
	if err != nil {
		diag.AdaptersErr = err.Error()
		diag.log()
		return nil
	}
	diag.Count = len(ads)
	s := &AMDSensors{lib: lib}
	seen := map[PCILoc]bool{}
	for _, a := range ads {
		loc := PCILoc{Bus: uint32(a.Bus), Device: uint32(a.Device), Function: uint32(a.Function)}
		line := fmt.Sprintf("#%d %s vendor=%04x present=%t exist=%t", a.Index, loc.String(), a.VendorID, a.Present, a.Exist)
		if loc.String() == "" {
			line = fmt.Sprintf("#%d bus=%d dev=%d fn=%d vendor=%04x present=%t exist=%t", a.Index, a.Bus, a.Device, a.Function, a.VendorID, a.Present, a.Exist)
		}
		switch {
		case a.VendorID != 0x1002 || a.Index < 0:
			line += " skipped"
		case seen[loc]:
			line += " same card"
		default:
			v, err := lib.OverdriveVersion(a.Index)
			switch {
			case err != nil:
				line += " overdrive=" + err.Error()
			case v < 5:
				line += " overdrive=" + strconv.Itoa(v) + " (too old)"
			default:
				line += " overdrive=" + strconv.Itoa(v)
				seen[loc] = true
				s.cards = append(s.cards, &adlCard{index: a.Index, version: v, loc: loc, name: a.Name})
			}
		}
		if len(diag.Adapters) < 16 {
			diag.Adapters = append(diag.Adapters, line)
		}
	}
	diag.Cards = len(s.cards)
	diag.log()
	if len(s.cards) == 0 {
		return nil
	}
	return s
}

// ADLDiagnosis is what ADL answered at start, logged in one line.
type ADLDiagnosis struct {
	Opened      string   // the DLL and ADL2_Main_Control_Create's return code
	AdaptersErr string   // ADL2_Adapter_NumberOfAdapters_Get / AdapterInfo_Get failed
	Count       int      // ADL adapters (one per display output)
	Adapters    []string // "#index bus:dev.fn vendor present exist overdrive=<version or error>"
	Cards       int      // AMD cards with Overdrive 5 or newer (temperature / watts read)
}

func (d ADLDiagnosis) log() {
	slog.Info("AMD GPU sensors (ADL)", "opened", d.Opened, "adapters", d.Count, "adapters_error", d.AdaptersErr,
		"per_adapter", d.Adapters, "cards", d.Cards)
}

// Cards lists the cards found (for the start-up log): "name (bus:dev.fn, Overdrive N)".
func (s *AMDSensors) Cards() []string {
	var out []string
	for _, c := range s.cards {
		out = append(out, c.name+" ("+c.loc.String()+", Overdrive "+strconv.Itoa(c.version)+")")
	}
	return out
}

func plausibleTemp(c float64) *float64 {
	if c <= 0 || c >= 150 {
		return nil
	}
	return P(Round(c, 1))
}

func plausibleWatts(w float64) *float64 {
	if w <= 0 || w > 1500 {
		return nil
	}
	return P(Round(w, 1))
}

// read returns one card's temperature and power (nil fields: not available). Errors are logged once per card.
func (s *AMDSensors) read(c *adlCard) AMDReading {
	var r AMDReading
	var errs []error
	switch {
	case c.version >= 8:
		sens, err := s.lib.PMLog(c.index)
		if err != nil {
			errs = append(errs, err)
			break
		}
		get := func(i int) (float64, bool) {
			if i < len(sens) && sens[i].Supported {
				return float64(sens[i].Value), true
			}
			return 0, false
		}
		if v, ok := get(pmlogTempEdge); ok {
			r.TempC = plausibleTemp(v)
		} else if v, ok := get(pmlogTempHotspot); ok {
			r.TempC = plausibleTemp(v)
		}
		if v, ok := get(pmlogBoardPower); ok {
			r.PowerW = plausibleWatts(v)
		}
		if r.PowerW == nil {
			if v, ok := get(pmlogASICPower); ok {
				r.PowerW = plausibleWatts(v)
			}
		}
	case c.version == 7:
		if m, err := s.lib.ODNTemperature(c.index); err == nil {
			r.TempC = plausibleTemp(float64(m) / 1000)
		} else {
			errs = append(errs, err)
		}
		if p, err := s.lib.OD6Power(c.index); err == nil {
			r.PowerW = plausibleWatts(float64(p) / 256)
		}
	case c.version == 6:
		if m, err := s.lib.OD6Temperature(c.index); err == nil {
			r.TempC = plausibleTemp(float64(m) / 1000)
		} else {
			errs = append(errs, err)
		}
		if p, err := s.lib.OD6Power(c.index); err == nil {
			r.PowerW = plausibleWatts(float64(p) / 256)
		}
	default:
		if m, err := s.lib.OD5Temperature(c.index); err == nil {
			r.TempC = plausibleTemp(float64(m) / 1000)
		} else {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 && !c.warned {
		c.warned = true
		slog.Debug("AMD GPU sensors (ADL): read failed; showing load and VRAM only", "card", c.name, "error", errs[0])
	}
	return r
}

// Attach fills temp_c / power_w of the AMD GPUs in gpus from ADL, matched by PCI location (or, when a location
// is unknown, the only AMD GPU to the only ADL card). Source becomes "amd" where something was filled.
func (s *AMDSensors) Attach(gpus []GPU) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var amd []int
	for i, g := range gpus {
		if g.Vendor == "amd" {
			amd = append(amd, i)
		}
	}
	for _, i := range amd {
		g := &gpus[i]
		var card *adlCard
		for _, c := range s.cards {
			if g.loc != nil && *g.loc == c.loc {
				card = c
				break
			}
		}
		if card == nil && g.loc == nil && len(amd) == 1 && len(s.cards) == 1 {
			card = s.cards[0]
		}
		if card == nil {
			continue
		}
		r := s.read(card)
		if r.TempC != nil {
			g.TempC = r.TempC
		}
		if r.PowerW != nil {
			g.PowerW = r.PowerW
		}
		if r.TempC != nil || r.PowerW != nil {
			g.Source = "amd"
		}
	}
}
