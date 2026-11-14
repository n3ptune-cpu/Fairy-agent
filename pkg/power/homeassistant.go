package power

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// HomeAssistantConfig is a `type: homeassistant` power source: the watts of one plug, read from the power
// sensor that a Home Assistant has for it (plugs Fairy cannot ask itself, such as Tuya ones).
type HomeAssistantConfig struct {
	Base     `yaml:",inline"`
	URL      string  `yaml:"url"`       // http://192.168.1.10:8123: Home Assistant itself, nothing after the port
	TokenEnv string  `yaml:"token_env"` // the environment variable that holds the long-lived access token
	Entity   string  `yaml:"entity"`    // sensor.desk_plug_power: the power sensor's entity id
	MaxAgeS  float64 `yaml:"max_age_s"` // 0 (default): not checked; else (1 s to a week) a value reported longer ago is no reading
	CAFile   string  `yaml:"ca_file"`   // https only: the certificate (or its CA) Home Assistant must show

	// Optional, each the entity id of one more sensor of the same plug (haExtras). A member that is there must
	// be a sensor's id like `entity`, and no two members of an entry name the same sensor.
	VoltageEntity string `yaml:"voltage_entity"` // sensor.desk_plug_voltage: volts
	CurrentEntity string `yaml:"current_entity"` // sensor.desk_plug_current: amperes
	EnergyEntity  string `yaml:"energy_entity"`  // sensor.desk_plug_energy: the energy total, kWh
}

// haExtra is one of the values a homeassistant entry can read besides the watts, each from a sensor of its
// own: the member of the entry that names the sensor, the member of the reading (and of the agent's row) the
// value goes into, and how the sensor's state is read (devices.ParseHAValue).
type haExtra struct {
	member string         // voltage_entity
	value  string         // voltage: the name the value has in a reading
	word   string         // voltage: the value's word in the config check's line
	kind   devices.HAKind // how its state object is read
	entity string         // sensor.desk_plug_voltage ("" in haExtras)
	addr   string         // the address asked for it, put together like homeAssistant.addr
}

// haExtras are the optional values in the order they are asked for, after the watts.
var haExtras = []haExtra{
	{member: "voltage_entity", value: "voltage", word: "voltage", kind: devices.HAVoltage},
	{member: "current_entity", value: "current", word: "current", kind: devices.HACurrent},
	{member: "energy_entity", value: "energy_kwh_total", word: "energy", kind: devices.HAEnergy},
}

// MaxHARequests is the most requests one reading of a homeassistant source makes: the watts and the three
// optional values, one request each.
//
// (As for every device type, Go's HTTP client sends a GET once more, on a new connection, when the kept
// connection it was sent on turns out to be dead before any byte of an answer came. Such a request was not
// answered. A request that was answered, with a refusal too, is never sent again.)
const MaxHARequests = 4

// haMinShare is the least time one of the optional values is asked with. With less left of the reading's
// timeout the value is not asked for at all (haNoTimeLeft): a request that can only time out is not sent.
const haMinShare = 50 * time.Millisecond

// haNoTimeLeft is why an optional value is missing when the reading's timeout was used up before its turn.
const haNoTimeLeft = "no time left in this reading (the requests before it took the timeout)"

// homeAssistant reads one sensor of a Home Assistant. It is read-only by what it can send at all, not by the
// token: a Home Assistant token carries no limits, whoever holds it can switch everything its user can (and a
// user that is not an administrator can switch every entity). So:
//
//   - the only request this type ever makes is GET <url>/api/states/<entity>, through devices.ReadJSON, which
//     has no other method. There is no code here for another path or for a body. One reading makes that
//     request for `entity` and then for each of voltage_entity, current_entity and energy_entity that the
//     entry has: at most MaxHARequests, one after the other (ReadPartial says why);
//   - every address is put together once, in buildHomeAssistant, from parts that were checked there: scheme
//     and host[:port] of `url` (nothing else is allowed in it) and an entity id that matches haEntity, so it
//     is a sensor's and holds no character that could change the path;
//   - a redirect is not followed (no client of pkg/devices does), so the token goes to those addresses only.
type homeAssistant struct {
	c      HomeAssistantConfig
	addr   string          // the address asked for the watts: scheme://host[:port]/api/states/<entity>
	extras []haExtra       // the optional values this entry has, in the order of haExtras
	host   string          // host[:port], for the config check's line
	maxAge time.Duration   // 0: off
	tr     *http.Transport // https: one transport of its own (the ca_file, connections reused); nil for http
}

// haEntity is what `entity` must be: the id of a sensor. Sensors only report; an id of anything that can be
// switched (switch.x, light.x) is refused when the config is read.
var haEntity = regexp.MustCompile(`^sensor\.[a-z0-9_]+$`)

var haEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// haSystemEnv are variables of the system that token_env must not name (buildHomeAssistant): the obvious ones,
// not every one there is.
var haSystemEnv = []string{"PATH", "HOME", "TEMP", "TMP", "SystemRoot", "USERPROFILE"}

// maxHAAgeS is the largest max_age_s: a week.
const maxHAAgeS = 7 * 24 * 3600

func (s *homeAssistant) Info() Base { return s.c.Base }

// Home Assistant itself hears from most plugs every 10 to 60 s: asking it more often shows nothing new.
func (s *homeAssistant) DefaultInterval() float64 { return 10 }
func (s *homeAssistant) FloorInterval() float64   { return 5 }
func (s *homeAssistant) MaxBackoff() float64      { return 60 }

// Check is this source's line for a config check: the host asked, the sensor, the sensors of the optional
// values ("voltage sensor.desk_plug_voltage, energy sensor.desk_plug_energy"), and whether the variable named
// by token_env is set. The token itself is not looked at.
func (s *homeAssistant) Check() Check {
	scheme, _, _ := strings.Cut(s.addr, "://")
	var also []string
	for _, x := range s.extras {
		also = append(also, x.word+" "+x.entity)
	}
	return Check{ID: s.c.ID, Type: s.c.Type, Scheme: scheme, Host: s.host, Reads: s.c.Entity, Also: strings.Join(also, ", "),
		SecretEnv: s.c.TokenEnv, SecretSet: os.Getenv(s.c.TokenEnv) != ""}
}

func (s *homeAssistant) Close() {
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
}

// Read asks Home Assistant for the sensor's state, and for the states of the optional values: ReadPartial
// without its reasons.
func (s *homeAssistant) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	rs, _, err := s.ReadPartial(ctx, timeout)
	return rs, err
}

// ReadPartial is one reading: one GET for the watts and, when that gave a reading, one GET for each optional
// value the entry has (voltage_entity, current_entity, energy_entity), in that order.
//
// The watts are the source's reading. Without them there is none: the error is the watts' error and no
// optional value is asked for (a value that would have been there is not shown with a failed source). With
// them, an optional value that cannot be read never makes the reading fail: the value is left out (nil) and
// missing has its reason under the value's name in the reading ("voltage", "current", "energy_kwh_total"), a
// fixed text of devices.ParseHAValue, of pkg/devices' requests ("timeout", "http 500") or of this file
// ("entity not found", haNoTimeLeft). missing is nil when nothing is missing.
//
// The one exception is a refusal of the token (401 or 403) for an optional value: that is a refusal of the
// whole source (Refused), with the member that was asked for in its words. The watts that were read a moment
// before are dropped with it. Home Assistant has counted a failed login, and a source that went on showing
// its watts would be asked again at its interval and count one more with every reading: the long wait after a
// refusal (RefusedWait) is for exactly this. Nothing more is asked for in that reading, so a reading never
// makes more than one request that is refused.
//
// The requests are made one after the other, not at the same time: a token that Home Assistant does not
// accept is then sent once in a reading and not four times at once (each counts as a failed login there), the
// one connection of the first request is used again for the others, and a small Home Assistant is never asked
// four things at once by every plug. A reading is asked for every 5 s at the most and Home Assistant answers
// a state from memory, so the time this costs is not missed.
//
// timeout is for the whole reading, as it is for every source: all requests together take no longer. The
// watts may use all of it, as they always could. What is left then is shared among the optional values: each
// is asked with an equal part of what is left when its turn comes (what one does not use, the next ones get),
// so that one sensor that does not answer cannot take the others' time. A part is never shorter than
// haMinShare; when less than that is left of the reading, a value is not asked for (haNoTimeLeft).
//
// The token is read from the environment for every reading, lives only as long as the reading and goes into
// the Authorization header of its requests only. It is never logged and never part of an error or a reason:
// devices.ReadJSON returns only fixed words for a failed request, the answer's body is not repeated anywhere
// (devices.ParseHAState and devices.ParseHAValue have fixed reasons), and haError checks once more.
func (s *homeAssistant) ReadPartial(ctx context.Context, timeout time.Duration) (rs []Reading, missing map[string]string, err error) {
	c := s.c
	tok, err := configutil.EnvSecret(c.TokenEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, nil, devices.Safe(err) // names the variable, never a value
	}
	if !headerText(tok) {
		return nil, nil, devices.Errf("power source %s: env var %s does not hold a token (it has a space or another character a token cannot have)", c.ID, c.TokenEnv)
	}
	deadline := time.Now().Add(timeout)
	get := func(addr string, within time.Duration, use func(d map[string]any) error) error {
		hc := devices.LANClient(within)
		if s.tr != nil {
			hc = devices.ClientWith(within, s.tr)
		}
		if err := devices.ReadJSON(ctx, hc, addr, "bearer", "", tok, use); err != nil {
			return haError(err, tok)
		}
		return nil
	}
	var r devices.Reading
	err = get(s.addr, timeout, func(d map[string]any) (err error) {
		r, err = devices.ParseHAState(d, s.maxAge, time.Now())
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	for i, x := range s.extras {
		reason := haNoTimeLeft
		if share, ask := haShare(time.Until(deadline), len(s.extras)-i); ask {
			var v float64
			err := get(x.addr, share, func(d map[string]any) (err error) {
				v, err = devices.ParseHAValue(d, x.kind, s.maxAge, time.Now())
				return err
			})
			switch {
			case err == nil:
				switch x.kind {
				case devices.HAVoltage:
					r.Voltage = &v
				case devices.HACurrent:
					r.Current = &v
				case devices.HAEnergy:
					r.EnergyKWh = &v
				}
				continue
			case Refused(err):
				return nil, nil, refusedf("home assistant refused the token (asked for %s)", x.member)
			}
			reason = devices.Describe(err)
		}
		if missing == nil {
			missing = map[string]string{}
		}
		missing[x.value] = reason
	}
	return []Reading{NewReading(c.Base, r)}, missing, nil
}

// haShare is the time one optional value is asked with when left is left of the reading's timeout and toAsk
// values are still to ask, this one among them: an equal part of what is left, and at least haMinShare (never
// more than is left: it is only given while that much is). ask is false when less than haMinShare is left.
func haShare(left time.Duration, toAsk int) (share time.Duration, ask bool) {
	if left < haMinShare || toAsk < 1 {
		return 0, false
	}
	return max(left/time.Duration(toAsk), haMinShare), true
}

// headerText reports whether a token can be sent in a header as it is: visible ASCII only, no space.
func headerText(tok string) bool {
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] >= 0x7f {
			return false
		}
	}
	return true
}

// haError gives Home Assistant's two usual refusals their own words and passes on the other errors that are
// fixed texts of pkg/devices ("timeout", "connection failed", "http 500", the parser's reasons). This is the
// second lock on the token: an error of any other kind, and one whose text held the token or the header (there
// is none today), is replaced by a fixed word.
func haError(err error, tok string) error {
	var he *devices.HTTPStatusError
	if errors.As(err, &he) {
		switch he.Code {
		case http.StatusUnauthorized, http.StatusForbidden:
			// 401: a wrong or revoked token, a disabled user, or a user that may not read this entity. Home
			// Assistant has counted this request as a failed login: the error is a refusal (Refused), after
			// which the source is asked again much later, not at its interval.
			return refusedf("home assistant refused the token")
		case http.StatusNotFound:
			return devices.Errf("entity not found")
		}
		return err
	}
	var de *devices.Error
	if !errors.As(err, &de) || strings.Contains(de.Msg, "Bearer") || (len(tok) >= 8 && strings.Contains(de.Msg, tok)) {
		return devices.Errf("request failed")
	}
	return err
}

// haMemberName is a member's name that an error may repeat: what a member of this type, or a misspelt one,
// looks like. Anything else that stands where a name should be is not shown.
var haMemberName = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// haDecode decodes an entry strictly, as DecodeStrict does (a member this type does not have is an error), but
// its errors are fixed words with the names of the members that are wrong, never a value: the YAML decoder's
// own error repeats the beginning of a value of the wrong kind ("cannot unmarshal !!str `<its first characters>...`"). To
// find the members, each is decoded alone, in the order of their names.
func haDecode(id string, raw map[string]any, c *HomeAssistantConfig) error {
	if DecodeStrict(raw, c) == nil {
		return nil
	}
	var wrong []string
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		one := map[string]any{k: raw[k]}
		if DecodeStrict(one, &HomeAssistantConfig{}) == nil {
			continue
		}
		b, err := yaml.Marshal(one)
		switch {
		case !haMemberName.MatchString(k):
			wrong = append(wrong, "a member with a name that no member of a homeassistant entry has")
		case err == nil && yaml.Unmarshal(b, &HomeAssistantConfig{}) == nil: // decodes when unknown members are let through
			wrong = append(wrong, "field "+k+" not found (a homeassistant entry has no such member)")
		default:
			wrong = append(wrong, k+": the value is of the wrong kind (such as text where a number belongs, or a list)")
		}
	}
	if wrong == nil {
		return fmt.Errorf("power source %s: invalid value", id)
	}
	return fmt.Errorf("power source %s: %s", id, strings.Join(slices.Compact(wrong), "; "))
}

// haAddress checks `url` and returns the one address this source asks and its host[:port]. The url must be
// Home Assistant itself: http or https, a host, optionally a port, and nothing else. A path, a query, a
// fragment or a user name would change what is asked, or would put a secret where it is logged.
func haAddress(raw, entity string) (addr, host string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil ||
		u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(raw, "?#@\\ ") || strings.HasSuffix(u.Host, ":") {
		return "", "", false
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", "", false
		}
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/api/states/" + entity}).String(), u.Host, true
}

// buildHomeAssistant validates a `type: homeassistant` entry.
//
// What its errors repeat of the entry, and nothing else of it: the entry's id when it is a valid id (that is
// how an entry is named), the names of members, and the path in ca_file when that file cannot be read or holds
// no certificate (the text of TLSConfig, which says which file). Never another member's value: a url with a
// password in it, or a token written into the file by mistake, is not repeated. That is why this type does
// not use the decoder the other types share, whose error repeats the first characters of a value of the wrong
// kind and an id of any kind (haDecode instead), and why an id that is not valid is not shown.
func buildHomeAssistant(raw map[string]any) (Source, error) {
	id, _ := raw["id"].(string)
	if !configutil.ValidID(id) {
		return nil, errors.New("power source of type homeassistant: id must be lowercase letters, digits and dashes")
	}
	var c HomeAssistantConfig
	if err := haDecode(id, raw, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !haEntity.MatchString(c.Entity) {
		return nil, fmt.Errorf("power source %s: entity must be the entity id of a sensor, like sensor.desk_plug_power (only sensor.* is read)", c.ID)
	}
	// The optional values: a member that is there (also an empty one) must be a sensor's id by the same rule,
	// and none of them names a sensor that another member of this entry names: the same state would be read
	// twice and shown as two different values. The errors name members, never an id that was given.
	named := map[string]string{c.Entity: "entity"}
	var extras []haExtra
	for _, x := range haExtras {
		if _, has := raw[x.member]; !has {
			continue
		}
		switch x.kind {
		case devices.HAVoltage:
			x.entity = c.VoltageEntity
		case devices.HACurrent:
			x.entity = c.CurrentEntity
		case devices.HAEnergy:
			x.entity = c.EnergyEntity
		}
		if !haEntity.MatchString(x.entity) {
			return nil, fmt.Errorf("power source %s: %s must be the entity id of a sensor, like sensor.desk_plug_%s (only sensor.* is read); leave the member out when the plug has no such sensor", c.ID, x.member, x.word)
		}
		if other, taken := named[x.entity]; taken {
			return nil, fmt.Errorf("power source %s: %s names the same sensor as %s: each value has a sensor of its own", c.ID, x.member, other)
		}
		named[x.entity] = x.member
		extras = append(extras, x)
	}
	addr, host, ok := haAddress(c.URL, c.Entity)
	if !ok {
		return nil, fmt.Errorf("power source %s: url must be the address of Home Assistant itself, http(s)://host[:port], with nothing after it (no path, query, fragment or user)", c.ID)
	}
	for i := range extras {
		extras[i].addr, _, _ = haAddress(c.URL, extras[i].entity) // the same url, checked just now
	}
	if !haEnvName.MatchString(c.TokenEnv) {
		return nil, fmt.Errorf("power source %s: token_env must be the name of the environment variable that holds the token (the token itself does not belong in this file)", c.ID)
	}
	// The value of the variable is sent to Home Assistant. Fairy's own variables hold Fairy's own secrets (the
	// agent's tokens, the panel's keys): none of them may be named here, in whatever letter case (Windows does
	// not tell the cases apart). `fairy-agent secret set` refuses such a name too.
	if strings.HasPrefix(strings.ToUpper(c.TokenEnv), "FAIRY_") {
		return nil, fmt.Errorf("power source %s: token_env must not be one of Fairy's own variables (a name that begins with FAIRY_): what such a variable holds is not for Home Assistant", c.ID)
	}
	// The variable is hidden from every program the agent starts (the agent hides what token_env names), and
	// its value goes to Home Assistant: a variable the system itself needs is neither a token nor one a
	// program can do without. The names are compared in whatever letter case, as Windows does. The error has
	// the whole list, not the name that was given.
	if slices.ContainsFunc(haSystemEnv, func(n string) bool { return strings.EqualFold(n, c.TokenEnv) }) {
		return nil, fmt.Errorf("power source %s: token_env must not be a variable of the system (%s): the variable named there is used for nothing but the token and is hidden from the programs the agent starts", c.ID, strings.Join(haSystemEnv, ", "))
	}
	// 0 or at least a second: a fraction of a second is not an age any plug's value can keep to (Home Assistant
	// hears from a plug every 10 to 60 s), so it would only ever show "older than max_age_s".
	if !(c.MaxAgeS == 0 || c.MaxAgeS >= 1 && c.MaxAgeS <= maxHAAgeS) { // "not inside": .nan fails too
		return nil, fmt.Errorf("power source %s: max_age_s must be 0 (not checked) or 1 to %d s", c.ID, maxHAAgeS)
	}
	s := &homeAssistant{c: c, addr: addr, host: host, extras: extras, maxAge: time.Duration(c.MaxAgeS * float64(time.Second))}
	https := strings.HasPrefix(addr, "https://")
	if c.CAFile != "" && !https {
		return nil, fmt.Errorf("power source %s: ca_file is only for an https url", c.ID)
	}
	if https {
		tc, err := TLSConfig(true, c.CAFile) // always verified: the token must not go to whoever answers
		if err != nil {
			return nil, fmt.Errorf("power source %s: %w", c.ID, err)
		}
		s.tr = devices.TLSTransport(tc)
	}
	return s, nil
}
