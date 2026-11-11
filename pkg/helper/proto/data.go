package proto

import (
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// StatusData is the answer to status.
type StatusData struct {
	Version   string   `json:"version"`
	Started   string   `json:"started"`  // RFC 3339
	Features  []string `json:"features"` // api.FeatureCoreTemp ...
	Watchdog  bool     `json:"watchdog"` // the fan watchdog runs
	SleepOK   bool     `json:"sleep_ok"`
	SleepNote string   `json:"sleep_note,omitempty"`
	// Power is the shutdown, reboot or sleep the helper scheduled and that is still pending (also one from
	// before the helper or the agent restarted: Windows goes on counting a shutdown down). Absent: none.
	// Older agents ignore the field; older helpers never send it.
	Power *PowerPending `json:"power_pending,omitempty"`
	// Proto is the highest protocol version this helper speaks (MaxVersion). Absent: a helper from before
	// Version2, which knows no challenge, no approval and no trust.
	Proto int `json:"proto,omitempty"`
	// Approval is the helper's approval check: off, required or broken, and what it trusts. Absent: an older
	// helper.
	Approval *api.ApprovalStatus `json:"approval,omitempty"`
}

// PowerPending is a pending power action in StatusData.
type PowerPending struct {
	Action string  `json:"action"`  // shutdown | reboot | sleep
	At     float64 `json:"at"`      // when it happens, unix seconds
	DelayS int     `json:"delay_s"` // the delay it was asked with
	By     string  `json:"by"`      // who asked
}

// CoreTempData is the answer to coretemp_read: an unparsed copy of Core Temp's shared memory (the agent parses
// and checks it, so the elevated helper never interprets it) and the name it was found under.
type CoreTempData struct {
	Name  string `json:"name"`
	Block []byte `json:"block"`
}

// SensorsData is the answer to ipmi_sensors: the BMC's readings in /metrics form.
type SensorsData struct {
	Temps    []collect.Temp    `json:"temps"`
	Fans     []collect.Fan     `json:"fans"`
	Voltages []collect.Voltage `json:"voltages"`
}

// MaxSensors bounds each list of SensorsData (a large board has about 60 sensors).
const MaxSensors = 512

// Bound cuts each list to MaxSensors.
func (s *SensorsData) Bound() {
	s.Temps = s.Temps[:min(len(s.Temps), MaxSensors)]
	s.Fans = s.Fans[:min(len(s.Fans), MaxSensors)]
	s.Voltages = s.Voltages[:min(len(s.Voltages), MaxSensors)]
}

// PowerData is the answer to power.
type PowerData struct {
	Action string `json:"action"`
}

// AutoData is the answer to fan_auto: the mode the fans are in now.
type AutoData struct {
	Mode string `json:"mode"`
}
