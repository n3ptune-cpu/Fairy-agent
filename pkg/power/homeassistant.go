package power

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	MaxAgeS  float64 `yaml:"max_age_s"` // 0 (default): not checked; else a value reported longer ago is no reading
	CAFile   string  `yaml:"ca_file"`   // https only: the certificate (or its CA) Home Assistant must show
}

// homeAssistant reads one sensor of a Home Assistant. It is read-only by what it can send at all, not by the
// token: a Home Assistant token carries no limits, whoever holds it can switch everything its user can (and a
// user that is not an administrator can switch every entity). So:
//
//   - the only request this type ever makes is GET <url>/api/states/<entity>, through devices.ReadJSON, which
//     has no other method. There is no code here for another path or for a body;
//   - the address is put together once, in buildHomeAssistant, from parts that were checked there: scheme and
//     host[:port] of `url` (nothing else is allowed in it) and an entity id that matches haEntity, so it is a
//     sensor's and holds no character that could change the path;
//   - a redirect is not followed (no client of pkg/devices does), so the token goes to that address only.
type homeAssistant struct {
	c      HomeAssistantConfig
	addr   string          // the one address asked: scheme://host[:port]/api/states/<entity>
	host   string          // host[:port], for the config check's line
	maxAge time.Duration   // 0: off
	tr     *http.Transport // https: one transport of its own (the ca_file, connections reused); nil for http
}

// haEntity is what `entity` must be: the id of a sensor. Sensors only report; an id of anything that can be
// switched (switch.x, light.x) is refused when the config is read.
var haEntity = regexp.MustCompile(`^sensor\.[a-z0-9_]+$`)

var haEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// maxHAAgeS is the largest max_age_s: a week.
const maxHAAgeS = 7 * 24 * 3600

func (s *homeAssistant) Info() Base { return s.c.Base }

// Home Assistant itself hears from most plugs every 10 to 60 s: asking it more often shows nothing new.
func (s *homeAssistant) DefaultInterval() float64 { return 10 }
func (s *homeAssistant) FloorInterval() float64   { return 5 }
func (s *homeAssistant) MaxBackoff() float64      { return 60 }

// Check is this source's line for a config check: the host asked, the sensor, and whether the variable named by
// token_env is set. The token itself is not looked at.
func (s *homeAssistant) Check() Check {
	scheme, _, _ := strings.Cut(s.addr, "://")
	return Check{ID: s.c.ID, Type: s.c.Type, Scheme: scheme, Host: s.host, Reads: s.c.Entity, SecretEnv: s.c.TokenEnv,
		SecretSet: os.Getenv(s.c.TokenEnv) != ""}
}

func (s *homeAssistant) Close() {
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
}

// Read asks Home Assistant for the sensor's state: one GET for every reading.
//
// The token is read from the environment for every request and goes into the Authorization header only. It is
// never logged and never part of an error: devices.ReadJSON returns only fixed words for a failed request, the
// answer's body is not repeated anywhere (devices.ParseHAState has fixed reasons), and haError checks once
// more.
func (s *homeAssistant) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	tok, err := configutil.EnvSecret(c.TokenEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err) // names the variable, never a value
	}
	if !headerText(tok) {
		return nil, devices.Errf("power source %s: env var %s does not hold a token (it has a space or another character a token cannot have)", c.ID, c.TokenEnv)
	}
	hc := devices.LANClient(timeout)
	if s.tr != nil {
		hc = devices.ClientWith(timeout, s.tr)
	}
	var r devices.Reading
	err = devices.ReadJSON(ctx, hc, s.addr, "bearer", "", tok, func(d map[string]any) (err error) {
		r, err = devices.ParseHAState(d, s.maxAge, time.Now())
		return err
	})
	if err != nil {
		return nil, haError(err, tok)
	}
	return []Reading{NewReading(c.Base, r)}, nil
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
			// 401: a wrong or revoked token, a disabled user, or a user that may not read this entity
			return devices.Errf("home assistant refused the token")
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

// buildHomeAssistant validates a `type: homeassistant` entry. Its errors name the entry and the member, never
// a member's value: a url with a password in it, or a token written into the file by mistake, is not repeated.
func buildHomeAssistant(decode configDecoder) (Source, error) {
	var c HomeAssistantConfig
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !haEntity.MatchString(c.Entity) {
		return nil, fmt.Errorf("power source %s: entity must be the entity id of a sensor, like sensor.desk_plug_power (only sensor.* is read)", c.ID)
	}
	addr, host, ok := haAddress(c.URL, c.Entity)
	if !ok {
		return nil, fmt.Errorf("power source %s: url must be the address of Home Assistant itself, http(s)://host[:port], with nothing after it (no path, query, fragment or user)", c.ID)
	}
	if !haEnvName.MatchString(c.TokenEnv) {
		return nil, fmt.Errorf("power source %s: token_env must be the name of the environment variable that holds the token (the token itself does not belong in this file)", c.ID)
	}
	if !(c.MaxAgeS >= 0 && c.MaxAgeS <= maxHAAgeS) { // "not inside": .nan fails too
		return nil, fmt.Errorf("power source %s: max_age_s must be 0 (not checked) to %d s", c.ID, maxHAAgeS)
	}
	s := &homeAssistant{c: c, addr: addr, host: host, maxAge: time.Duration(c.MaxAgeS * float64(time.Second))}
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
