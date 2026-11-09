package collect

// Radeon temperature and power on Windows from AMD's own user-mode library, ADL (atiadlxx.dll, which the
// Adrenalin driver installs; atiadlxy.dll as a fallback). Read only: only ...Get / Query functions are called,
// never a Set or any Overdrive write; no driver of our own and nothing read from other processes. Per card the
// temperature calls are tried in the order its Overdrive version suggests (tempAPIs), the first that answers is
// remembered:
//
//	8 (Navi and newer, e.g. RX 5600 XT): ADL2_New_QueryPMLogData_Get -> PMLog sensors: edge temperature (8, else
//	  hotspot 27) in °C, board power (73, newer drivers) else ASIC power (23) in W; then OverdriveN, Overdrive6
//	7 (OverdriveN, Polaris / Vega): ADL2_OverdriveN_Temperature_Get (edge, m°C), then PMLog, Overdrive6;
//	  power ADL2_Overdrive6_CurrentPower_Get
//	6: ADL2_Overdrive6_Temperature_Get (m°C), ADL2_Overdrive6_CurrentPower_Get (total, 1/256 W)
//	5: ADL2_Overdrive5_Temperature_Get (m°C)
//	unknown (ADL2_Overdrive_Caps failed): all of them; the card is kept only when one answers
//
// ADL is opened for all adapters (not only those driving a display: a service in session 0 sees its Radeon
// with present=0) and gives AMD's vendor id as decimal 1002. It lists one "adapter" per display output /
// logical adapter; they are grouped by PCI location, which is also how they are matched to the cards found
// through DXGI and D3DKMT (wingpu.go). This file holds the platform-independent part, over the ADLLib
// interface (the DLL on Windows, a fake in tests).

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
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

// The temperature calls, by name (the start-up line and Cards say which one answered).
const (
	apiPMLog = "PMLog"      // ADL2_New_QueryPMLogData_Get (Overdrive 8: Navi and newer)
	apiODN   = "OverdriveN" // ADL2_OverdriveN_Temperature_Get (Overdrive 7: Polaris / Vega; often Navi too)
	apiOD6   = "Overdrive6" // ADL2_Overdrive6_Temperature_Get
	apiOD5   = "Overdrive5" // ADL2_Overdrive5_Temperature_Get
)

// tempAPIs is the order the temperature calls are tried in, by Overdrive version (0: ADL2_Overdrive_Caps did
// not answer, e.g. in a service's session 0: every call is tried). All of them only read.
func tempAPIs(version int) []string {
	switch {
	case version >= 8:
		return []string{apiPMLog, apiODN, apiOD6}
	case version == 7:
		return []string{apiODN, apiPMLog, apiOD6}
	case version == 6:
		return []string{apiOD6, apiODN}
	case version == 5:
		return []string{apiOD5}
	default:
		return []string{apiPMLog, apiODN, apiOD6, apiOD5}
	}
}

type adlCard struct {
	index   int
	version int // Overdrive version; 0: unknown (ADL2_Overdrive_Caps failed)
	loc     PCILoc
	name    string
	apis    []string
	api     string // the temperature call that answered last ("" none yet)
	warned  bool
}

// AMDSensors reads Radeon temperature / power through ADL and attaches them to the matching GPUs.
type AMDSensors struct {
	lib   ADLLib
	mu    sync.Mutex
	cards []*adlCard
}

// adlVendor is the PCI vendor id of an ADL adapter. ADL gives AMD's as the decimal number 1002 (0x3ea, logged
// "vendor=03ea" by 0.5.2, which therefore skipped every Radeon), not 0x1002; both mean AMD.
func adlVendor(v int) int {
	if v == 1002 {
		return 0x1002
	}
	return v
}

func (a ADLAdapter) loc() PCILoc {
	return PCILoc{Bus: uint32(a.Bus), Device: uint32(a.Device), Function: uint32(a.Function)}
}

// adlCandidates orders the ADL adapters to try: AMD only (vendor 1002), those that exist or are present first
// (ADL's own order kept otherwise). A service in session 0 sees its Radeon with present=0 (no interactive
// desktop), so present is not required; an entry that neither exists nor is present is tried last. The
// returned reasons say, per adapter (by its position in ads), why it is not a candidate ("" when it is).
func adlCandidates(ads []ADLAdapter) (order []int, reasons []string) {
	reasons = make([]string, len(ads))
	var later []int
	for i, a := range ads {
		switch {
		case adlVendor(a.VendorID) != 0x1002:
			reasons[i] = "skipped (not AMD)"
		case a.Index < 0:
			reasons[i] = "skipped (no index)"
		case a.Exist || a.Present:
			order = append(order, i)
		default:
			later = append(later, i)
		}
	}
	return append(order, later...), reasons
}

// NewAMDSensors lists the AMD cards ADL knows (one per PCI location: ADL lists one adapter per display output
// or logical adapter); nil when there is none or ADL fails. Per card it tries a reading at once, to log which
// temperature call answers. It logs one line saying what ADL answered (ADLDiagnosis): when a Radeon gets no
// temperature, that line tells why.
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
	order, notes := adlCandidates(ads)
	byLoc := map[PCILoc]int{} // the card kept per location (index into s.cards)
	for _, i := range order {
		a := ads[i]
		loc := a.loc()
		k, seen := byLoc[loc]
		if seen && s.cards[k].api != "" {
			notes[i] = "same card"
			continue
		}
		c := &adlCard{index: a.Index, loc: loc, name: a.Name}
		v, err := lib.OverdriveVersion(a.Index)
		switch {
		case err != nil:
			notes[i] = "overdrive=" + err.Error()
		case v < 5:
			notes[i] = "overdrive=" + strconv.Itoa(v) + " (too old)"
		default:
			notes[i] = "overdrive=" + strconv.Itoa(v)
			c.version = v
		}
		c.apis = tempAPIs(c.version)
		r, errs := s.readCard(c)
		switch {
		case r.TempC != nil:
			notes[i] += fmt.Sprintf(" temp=%s %.1fC", c.api, *r.TempC)
		case len(errs) > 0:
			notes[i] += " temp=none (" + strings.Join(errs, "; ") + ")"
		default:
			notes[i] += " temp=none"
		}
		if r.PowerW != nil {
			notes[i] += fmt.Sprintf(" power=%.1fW", *r.PowerW)
		}
		switch {
		case seen && c.api != "":
			// the card kept for this location gave no temperature at start, this entry of it does: use it
			notes[i] += " (used instead of #" + strconv.Itoa(s.cards[k].index) + ")"
			s.cards[k] = c
		case seen:
			notes[i] += " same card"
		case c.version >= 5 || r.TempC != nil || r.PowerW != nil:
			// a card with a known Overdrive version is kept even when the first reading failed (tried again
			// each time); without one, only when a call answered
			byLoc[loc] = len(s.cards)
			s.cards = append(s.cards, c)
		}
	}
	for _, c := range s.cards {
		api := c.api
		if api == "" {
			api = "none"
		}
		diag.TempAPI = append(diag.TempAPI, c.loc.String()+" "+api)
	}
	for i, a := range ads {
		if len(diag.Adapters) >= 16 {
			break
		}
		loc := a.loc()
		line := fmt.Sprintf("#%d %s vendor=%04x present=%t exist=%t", a.Index, loc.String(), adlVendor(a.VendorID), a.Present, a.Exist)
		if loc.String() == "" {
			line = fmt.Sprintf("#%d bus=%d dev=%d fn=%d vendor=%04x present=%t exist=%t", a.Index, a.Bus, a.Device, a.Function, adlVendor(a.VendorID), a.Present, a.Exist)
		}
		if notes[i] != "" {
			line += " " + notes[i]
		}
		diag.Adapters = append(diag.Adapters, line)
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
	Count       int      // ADL adapters (one per display output / logical adapter)
	Adapters    []string // "#index bus:dev.fn vendor present exist overdrive=<version or error> temp=<call> ..."
	Cards       int      // AMD cards read (one per PCI location)
	TempAPI     []string // per card "bus:dev.fn <the temperature call that answered at start, or none>"
}

func (d ADLDiagnosis) log() {
	slog.Info("AMD GPU sensors (ADL)", "opened", d.Opened, "adapters", d.Count, "adapters_error", d.AdaptersErr,
		"per_adapter", d.Adapters, "cards", d.Cards, "temp_api", d.TempAPI)
}

// Cards lists the cards found (for the start-up log): "name (bus:dev.fn, Overdrive N, temperature via X)".
func (s *AMDSensors) Cards() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.cards {
		od := "Overdrive " + strconv.Itoa(c.version)
		if c.version == 0 {
			od = "Overdrive unknown"
		}
		api := c.api
		if api == "" {
			api = "none yet"
		}
		out = append(out, c.name+" ("+c.loc.String()+", "+od+", temperature via "+api+")")
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

// readAPI runs one temperature call (PMLog also gives the power).
func (s *AMDSensors) readAPI(api string, index int) (AMDReading, error) {
	var r AMDReading
	milli := func(m int, err error) (AMDReading, error) {
		if err != nil {
			return r, err
		}
		r.TempC = plausibleTemp(float64(m) / 1000)
		return r, nil
	}
	switch api {
	case apiPMLog:
		sens, err := s.lib.PMLog(index)
		if err != nil {
			return r, err
		}
		get := func(i int) (float64, bool) {
			if i < len(sens) && sens[i].Supported {
				return float64(sens[i].Value), true
			}
			return 0, false
		}
		if v, ok := get(pmlogTempEdge); ok {
			r.TempC = plausibleTemp(v)
		}
		if r.TempC == nil {
			if v, ok := get(pmlogTempHotspot); ok {
				r.TempC = plausibleTemp(v)
			}
		}
		if v, ok := get(pmlogBoardPower); ok {
			r.PowerW = plausibleWatts(v)
		}
		if r.PowerW == nil {
			if v, ok := get(pmlogASICPower); ok {
				r.PowerW = plausibleWatts(v)
			}
		}
		return r, nil
	case apiODN:
		return milli(s.lib.ODNTemperature(index))
	case apiOD6:
		return milli(s.lib.OD6Temperature(index))
	default:
		return milli(s.lib.OD5Temperature(index))
	}
}

// readCard tries the card's temperature calls, the one that answered last first, and remembers which one gave a
// temperature. Power comes from PMLog, else (Overdrive 6 / 7 / unknown) from ADL2_Overdrive6_CurrentPower_Get.
// errs are "call: error" for each call that failed.
func (s *AMDSensors) readCard(c *adlCard) (AMDReading, []string) {
	var r AMDReading
	var errs []string
	apis := c.apis
	if c.api != "" {
		apis = append([]string{c.api}, slices.DeleteFunc(slices.Clone(c.apis), func(a string) bool { return a == c.api })...)
	}
	for _, api := range apis {
		got, err := s.readAPI(api, c.index)
		if err != nil {
			errs = append(errs, api+": "+err.Error())
			continue
		}
		if r.PowerW == nil {
			r.PowerW = got.PowerW
		}
		if got.TempC != nil {
			r.TempC, c.api = got.TempC, api
			break
		}
		errs = append(errs, api+": no plausible temperature")
	}
	if r.PowerW == nil && (c.version == 0 || c.version == 6 || c.version == 7) {
		if p, err := s.lib.OD6Power(c.index); err == nil {
			r.PowerW = plausibleWatts(float64(p) / 256)
		}
	}
	return r, errs
}

// read returns one card's temperature and power (nil fields: not available). Failures are logged once per card.
func (s *AMDSensors) read(c *adlCard) AMDReading {
	r, errs := s.readCard(c)
	if r.TempC == nil && len(errs) > 0 && !c.warned {
		c.warned = true
		slog.Debug("AMD GPU sensors (ADL): no temperature; showing load and VRAM only", "card", c.name, "error", strings.Join(errs, "; "))
	}
	return r
}

// Attach fills temp_c / power_w of the AMD GPUs in gpus from ADL, matched by PCI location (D3DKMT's for the
// DXGI cards). A GPU whose location is unknown gets the one ADL card that no located AMD GPU took, when it is
// the only such GPU (no guessing between two). Source becomes "amd" where something was filled.
func (s *AMDSensors) Attach(gpus []GPU) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	card := matchADLCards(gpus, s.cards)
	for i, c := range card {
		if c == nil {
			continue
		}
		g := &gpus[i]
		r := s.read(c)
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

// matchADLCards pairs the AMD GPUs with ADL cards: by PCI location, then the one card left over to the one AMD
// GPU without a known location. The result is indexed like gpus (nil: no card).
func matchADLCards(gpus []GPU, cards []*adlCard) []*adlCard {
	out := make([]*adlCard, len(gpus))
	taken := map[*adlCard]bool{}
	var unlocated []int
	for i, g := range gpus {
		if g.Vendor != "amd" {
			continue
		}
		if !g.loc.Known() {
			unlocated = append(unlocated, i)
			continue
		}
		for _, c := range cards {
			if !taken[c] && *g.loc == c.loc {
				out[i], taken[c] = c, true
				break
			}
		}
	}
	var left []*adlCard
	for _, c := range cards {
		if !taken[c] {
			left = append(left, c)
		}
	}
	if len(unlocated) == 1 && len(left) == 1 {
		out[unlocated[0]] = left[0]
	}
	return out
}
