package proto

import "github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"

// StatusData is the answer to status.
type StatusData struct {
	Version   string   `json:"version"`
	Started   string   `json:"started"`  // RFC 3339
	Features  []string `json:"features"` // api.FeatureCoreTemp ...
	Watchdog  bool     `json:"watchdog"` // the fan watchdog runs
	SleepOK   bool     `json:"sleep_ok"`
	SleepNote string   `json:"sleep_note,omitempty"`
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
