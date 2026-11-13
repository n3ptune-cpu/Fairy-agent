package power

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// haTokenEnv is the variable the tests keep the made-up token in. Not a FAIRY_ name: those are refused.
const haTokenEnv = "POWER_TEST_HA_TOKEN"

// fakeHAToken is a made-up token, put together when the test runs: no text in this file looks like a
// credential (a real long-lived token of Home Assistant is a long signed text; nothing here depends on that).
func fakeHAToken() string { return strings.Join([]string{"fake", "ha", "token", "for", "tests"}, "-") }

type haRequest struct {
	method, uri, auth, accept string
	bodyBytes                 int
}

// fakeHA stands in for a Home Assistant: it records every request and answers GET /api/states/<entity> for
// the one sensor it has, for the one token it knows, as Home Assistant does (401 without a valid token, 404
// for another entity, 405 for another method there). answer, when set, replaces the sensor's state object.
type fakeHA struct {
	entity string
	answer func(w http.ResponseWriter, r *http.Request)

	mu   sync.Mutex
	reqs []haRequest
}

// haStateBody is a power sensor's state object as GET /api/states/<entity id> answers it.
func haStateBody(state, unit string, reported, updated time.Time) string {
	stamp := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000+00:00") }
	d := map[string]any{"entity_id": "sensor.desk_plug_power", "state": state,
		"attributes":   map[string]any{"state_class": "measurement", "unit_of_measurement": unit, "device_class": "power", "friendly_name": "Desk plug Power"},
		"last_changed": stamp(updated), "last_updated": stamp(updated),
		"context": map[string]any{"id": "ctx-1", "parent_id": nil, "user_id": nil}}
	if !reported.IsZero() {
		d["last_reported"] = stamp(reported)
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func (h *fakeHA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.reqs = append(h.reqs, haRequest{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Accept"), len(body)})
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Header.Get("Authorization") != "Bearer "+fakeHAToken():
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "401: Unauthorized")
	case !strings.HasPrefix(r.URL.Path, "/api/states/"):
		http.NotFound(w, r)
	case r.Method != http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)
	case r.URL.Path != "/api/states/"+h.entity:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Entity not found."}`)
	case h.answer != nil:
		h.answer(w, r)
	default:
		_, _ = io.WriteString(w, haStateBody("95.5", "W", time.Now().Add(-2*time.Second), time.Now().Add(-20*time.Second)))
	}
}

func (h *fakeHA) seen() []haRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]haRequest(nil), h.reqs...)
}

// startHA runs a fake Home Assistant with the sensor sensor.desk_plug_power and sets the token's variable.
func startHA(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) (*fakeHA, *httptest.Server) {
	t.Helper()
	ha := &fakeHA{entity: "sensor.desk_plug_power", answer: answer}
	srv := httptest.NewServer(ha)
	t.Cleanup(srv.Close)
	t.Setenv(haTokenEnv, fakeHAToken())
	return ha, srv
}

func haEntry(base string, more map[string]any) map[string]any {
	e := map[string]any{"id": "desk", "type": "homeassistant", "name": "Desk plug", "url": base, "token_env": haTokenEnv,
		"entity": "sensor.desk_plug_power", "system": "pc"}
	for k, v := range more {
		if v == nil {
			delete(e, k)
		} else {
			e[k] = v
		}
	}
	return e
}

func haSource(t *testing.T, base string, more map[string]any) Source {
	t.Helper()
	s, err := Build(haEntry(base, more), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// One reading is one request: GET <url>/api/states/<entity> with the token in the Authorization header, and
// nothing else. That is all this type ever sends, whatever the url is written like.
func TestHomeAssistantAsksForOneSensorOnly(t *testing.T) {
	for _, tail := range []string{"", "/"} {
		ha, srv := startHA(t, nil)
		s := haSource(t, srv.URL+tail, nil)
		for i := 0; i < 3; i++ {
			rs, err := s.Read(context.Background(), 2*time.Second)
			if err != nil || len(rs) != 1 {
				t.Fatalf("url with %q, read %d: %+v %v", tail, i, rs, err)
			}
			r := rs[0]
			if r.Watts == nil || *r.Watts != 95.5 || r.SourceID != "desk" || r.Name != "Desk plug" || r.SystemID == nil || *r.SystemID != "pc" ||
				r.Voltage != nil || r.Current != nil || r.EnergyKWhTotal != nil || time.Since(r.Timestamp) > time.Minute {
				t.Fatalf("read %d: %s", i, mustJSON(r))
			}
		}
		reqs := ha.seen()
		if len(reqs) != 3 {
			t.Errorf("url with %q: %d requests for 3 readings", tail, len(reqs))
		}
		for i, q := range reqs {
			if q.method != http.MethodGet || q.uri != "/api/states/sensor.desk_plug_power" || q.auth != "Bearer "+fakeHAToken() ||
				q.accept != "application/json" || q.bodyBytes != 0 {
				t.Errorf("url with %q, request %d: %s %s, Accept %q, %d bytes of body, token as expected: %v", tail, i, q.method, q.uri,
					q.accept, q.bodyBytes, q.auth == "Bearer "+fakeHAToken())
			}
		}
	}
	// the defaults: asked every 10 s, never more often than every 5 s
	s := haSource(t, "http://192.0.2.1:8123", nil)
	if s.DefaultInterval() != 10 || s.FloorInterval() != 5 || s.MaxBackoff() != 60 || s.Info().Type != "homeassistant" {
		t.Errorf("%v %v %v %q", s.DefaultInterval(), s.FloorInterval(), s.MaxBackoff(), s.Info().Type)
	}
}

// What Home Assistant answers, read through the real request: units, states that are no reading, and the age.
func TestHomeAssistantReadings(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		body   string
		maxAge any // max_age_s of the entry, nil: not set
		watts  float64
		reason string
	}{
		"watts":                     {haStateBody("41.7", "W", now, now), nil, 41.7, ""},
		"kilowatts":                 {haStateBody("0.0234", "kW", now, now), nil, 23.4, ""},
		"milliwatts":                {haStateBody("23456", "mW", now, now), nil, 23.456, ""},
		"megawatts":                 {haStateBody("0.0005", "MW", now, now), nil, 500, ""},
		"standby, zero":             {haStateBody("0.0", "W", now, now), nil, 0, ""},
		"no unit, a power sensor":   {`{"state":"12","attributes":{"device_class":"power"}}`, nil, 12, ""},
		"no unit, no class":         {`{"state":"12","attributes":{}}`, nil, 0, "home assistant: the sensor has no unit and is not a power sensor"},
		"energy, not power":         {haStateBody("12", "kWh", now, now), nil, 0, "home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)"},
		"unavailable":               {haStateBody("unavailable", "W", now, now), nil, 0, "home assistant: the sensor is unavailable"},
		"unknown":                   {haStateBody("unknown", "W", now, now), nil, 0, "home assistant: the sensor's state is unknown"},
		"empty":                     {haStateBody("", "W", now, now), nil, 0, "home assistant: the sensor has no state"},
		"not a number":              {haStateBody("on", "W", now, now), nil, 0, "home assistant: the sensor's state is not a number"},
		"NaN":                       {haStateBody("NaN", "W", now, now), nil, 0, "home assistant: the sensor's state is not a number"},
		"negative":                  {haStateBody("-3", "W", now, now), nil, 0, "home assistant: the sensor's value is not a possible power (0 to 100000 W)"},
		"absurd":                    {haStateBody("250", "kW", now, now), nil, 0, "home assistant: the sensor's value is not a possible power (0 to 100000 W)"},
		"null":                      {`null`, nil, 0, "home assistant: the sensor has no state"},
		"an empty object":           {`{}`, nil, 0, "home assistant: the sensor has no state"},
		"a list of states":          {`[{"state":"12","attributes":{"unit_of_measurement":"W"}}]`, nil, 0, "invalid JSON from device"},
		"old value, no max_age_s":   {haStateBody("41.7", "W", now.Add(-48*time.Hour), now.Add(-48*time.Hour)), nil, 41.7, ""},
		"old value, max_age_s 0":    {haStateBody("41.7", "W", now.Add(-48*time.Hour), now.Add(-48*time.Hour)), 0, 41.7, ""},
		"reported in time":          {haStateBody("41.7", "W", now.Add(-5*time.Minute), now.Add(-9*time.Hour)), 900, 41.7, ""},
		"reported too long ago":     {haStateBody("41.7", "W", now.Add(-20*time.Minute), now.Add(-time.Second)), 900, 0, "home assistant: the sensor's value is older than max_age_s"},
		"no last_reported, updated": {haStateBody("41.7", "W", time.Time{}, now.Add(-5*time.Minute)), 900, 41.7, ""},
		"no last_reported, old":     {haStateBody("41.7", "W", time.Time{}, now.Add(-20*time.Minute)), 900, 0, "home assistant: the sensor's value is older than max_age_s"},
		"no time at all":            {`{"state":"12","attributes":{"unit_of_measurement":"W"}}`, 900.5, 0, "home assistant: the sensor's state has no time (max_age_s is set)"},
	} {
		_, srv := startHA(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, c.body) })
		s := haSource(t, srv.URL, map[string]any{"max_age_s": c.maxAge})
		rs, err := s.Read(context.Background(), 2*time.Second)
		if c.reason != "" {
			if err == nil || len(rs) != 0 || devices.Describe(err) != c.reason {
				t.Errorf("%s: want %q, got %+v %v", name, c.reason, rs, err)
			}
			continue
		}
		if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != c.watts || math.Signbit(*rs[0].Watts) {
			t.Errorf("%s: want %v W, got %s %v", name, c.watts, mustJSON(rs), err)
		}
	}
}

// Home Assistant's refusals have their own words; no other status is followed or read.
func TestHomeAssistantStatusWords(t *testing.T) {
	var elsewhereHits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereHits.Add(1)
		_, _ = io.WriteString(w, haStateBody("31337", "W", time.Now(), time.Now()))
	}))
	defer elsewhere.Close()
	good := haStateBody("31337", "W", time.Now(), time.Now()) // a body that would be a reading if it were read
	status := func(code int) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code); _, _ = io.WriteString(w, good) }
	}
	redirect := func(code int, to func(r *http.Request) string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", to(r))
			w.WriteHeader(code)
			_, _ = io.WriteString(w, good)
		}
	}
	for name, c := range map[string]struct {
		answer func(w http.ResponseWriter, r *http.Request)
		want   string
	}{
		"401":                           {status(401), "home assistant refused the token"},
		"403":                           {status(403), "home assistant refused the token"},
		"404":                           {status(404), "entity not found"},
		"400":                           {status(400), "http 400"},
		"405":                           {status(405), "http 405"},
		"429":                           {status(429), "http 429"},
		"500":                           {status(500), "http 500"},
		"502, a proxy in front":         {status(502), "http 502"},
		"302 to another server":         {redirect(302, func(r *http.Request) string { return elsewhere.URL + r.URL.Path }), "http 302"},
		"301 to another server":         {redirect(301, func(r *http.Request) string { return elsewhere.URL + r.URL.Path }), "http 301"},
		"307 to another server":         {redirect(307, func(r *http.Request) string { return elsewhere.URL + r.URL.Path }), "http 307"},
		"308 to another server":         {redirect(308, func(r *http.Request) string { return elsewhere.URL + r.URL.Path }), "http 308"},
		"302 to the list of all states": {redirect(302, func(*http.Request) string { return "/api/states" }), "http 302"},
		"302 to a service call":         {redirect(302, func(*http.Request) string { return "/api/services/switch/turn_off" }), "http 302"},
		"302 to the same address":       {redirect(302, func(r *http.Request) string { return r.URL.Path }), "http 302"},
	} {
		ha, srv := startHA(t, c.answer)
		s := haSource(t, srv.URL, nil)
		rs, err := s.Read(context.Background(), 2*time.Second)
		if err == nil || len(rs) != 0 || devices.Describe(err) != c.want || err.Error() != c.want {
			t.Errorf("%s: want %q, got %+v %v", name, c.want, rs, err)
		}
		if reqs := ha.seen(); len(reqs) != 1 || reqs[0].method != http.MethodGet || reqs[0].uri != "/api/states/sensor.desk_plug_power" {
			t.Errorf("%s: want the one request, got %d: %+v", name, len(reqs), requestLines(reqs))
		}
	}
	if n := elsewhereHits.Load(); n != 0 {
		t.Errorf("a redirect was followed: %d requests reached the other server", n)
	}

	// the fake Home Assistant's own refusals: a token it does not know, an entity it does not have
	ha, srv := startHA(t, nil)
	t.Setenv(haTokenEnv, strings.Join([]string{"another", "token"}, "-"))
	if _, err := haSource(t, srv.URL, nil).Read(context.Background(), 2*time.Second); err == nil || err.Error() != "home assistant refused the token" {
		t.Errorf("a wrong token: %v", err)
	}
	t.Setenv(haTokenEnv, fakeHAToken())
	if _, err := haSource(t, srv.URL, map[string]any{"entity": "sensor.renamed_plug_power"}).Read(context.Background(), 2*time.Second); err == nil || err.Error() != "entity not found" {
		t.Errorf("an entity Home Assistant does not have: %v", err)
	}
	if reqs := ha.seen(); len(reqs) != 2 {
		t.Errorf("a refused reading is one request, not %d for two", len(reqs))
	}
}

func requestLines(reqs []haRequest) []string {
	var out []string
	for _, q := range reqs {
		out = append(out, q.method+" "+q.uri)
	}
	return out
}

// An answer over the shared limits of pkg/devices is given up, not read: 256 KiB, 8192 values, 32 levels. An
// honest state object, also one with many attributes, is far below them.
func TestHomeAssistantAnswerIsLimited(t *testing.T) {
	head := `{"state":"95.5","attributes":{"unit_of_measurement":"W","device_class":"power",`
	for name, c := range map[string]struct{ body, want string }{
		"300 KiB in one attribute": {head + `"friendly_name":"` + strings.Repeat("a", 300<<10) + `"}}`, "answer from device is too large (over 256 KiB)"},
		"4 MiB after the reading":  {head + `"x":"` + strings.Repeat("a", 4<<20) + `"}}`, "answer from device is too large (over 256 KiB)"},
		"an endless answer":        {head + `"x":"`, "answer from device is too large (over 256 KiB)"},
		"9000 values":              {head + `"x":[` + strings.TrimSuffix(strings.Repeat("0,", 9000), ",") + `]}}`, "answer from device has too many values (over 8192)"},
		"40 levels":                {head + `"x":` + chainOf(`{"":`, "0", "}", 40) + `}}`, "answer from device is nested too deep (over 32 levels)"},
	} {
		var sent atomic.Int64
		_, srv := startHA(t, func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.WriteString(w, c.body)
			sent.Add(int64(n))
			for name == "an endless answer" && r.Context().Err() == nil && sent.Load() < 64<<20 {
				n, err := io.WriteString(w, strings.Repeat("a", 32<<10))
				if sent.Add(int64(n)); err != nil {
					return
				}
			}
		})
		s := haSource(t, srv.URL, nil)
		rs, total, err := readCost(s)
		if err == nil || len(rs) != 0 || devices.Describe(err) != c.want {
			t.Errorf("%s: want %q, got %+v %v", name, c.want, rs, err)
		}
		if total > maxReadCost {
			t.Errorf("%s: allocated %d KiB (limit %d KiB)", name, total>>10, maxReadCost>>10)
		}
		if name == "an endless answer" && sent.Load() >= 64<<20 {
			t.Errorf("%s: the source went on reading: %d MiB were taken", name, sent.Load()>>20)
		}
		srv.CloseClientConnections()
	}
	// just inside the size limit: read
	body := head + `"friendly_name":"` + strings.Repeat("a", limitBytes-len(head)-64) + `"}}`
	_, srv := startHA(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
	if rs, err := haSource(t, srv.URL, nil).Read(context.Background(), 5*time.Second); err != nil || len(rs) != 1 || *rs[0].Watts != 95.5 {
		t.Errorf("an answer of %d bytes, inside the limit: %+v %v", len(body), rs, err)
	}
}

// What a `type: homeassistant` entry may hold. The entity rule is the read-only promise: only an id that
// begins with "sensor." and has no character that could change the request's path is ever asked for.
func TestHomeAssistantConfig(t *testing.T) {
	good := []map[string]any{
		nil,
		{"url": "http://192.0.2.10:8123/"},
		{"url": "https://ha.example.net"},
		{"url": "https://ha.example.net:443/"},
		{"url": "HTTP://homeassistant.local:8123"},
		{"url": "http://[fd00::10]:8123"},
		{"url": "http://100.101.102.103:8123"},
		{"entity": "sensor.a"},
		{"entity": "sensor.plug_3_power_2"},
		{"entity": "sensor.0"},
		{"entity": "sensor._"},
		{"token_env": "_HA1"},
		{"token_env": "ha_token"},
		{"token_env": "FAIRY"},        // not the prefix FAIRY_
		{"token_env": "FAIRYTALE_HA"}, // the same
		{"token_env": "HA_FAIRY_TOKEN"},
		{"token_env": "_FAIRY_TOKEN"},
		{"max_age_s": 0},
		{"max_age_s": 0.5},
		{"max_age_s": 900},
		{"max_age_s": 604800},
		{"interval": 30.0},
		{"interval": 1.0}, // accepted like for every type; FloorInterval makes it 5 s where it is used
		{"name": nil, "system": nil, "include_in_total": false},
	}
	for _, more := range good {
		s, err := Build(haEntry("http://192.0.2.10:8123", more), nil)
		if err != nil {
			t.Errorf("%v: %v", more, err)
			continue
		}
		s.Close()
	}

	const secretInURL = "PASSWORD-IN-THE-URL"
	bad := map[string]struct {
		more map[string]any
		want string
	}{
		// url: Home Assistant itself, nothing after host[:port]
		"url missing":                    {map[string]any{"url": nil}, "url must be"},
		"url empty":                      {map[string]any{"url": ""}, "url must be"},
		"url without a scheme":           {map[string]any{"url": "192.0.2.10:8123"}, "url must be"},
		"url, a name without a scheme":   {map[string]any{"url": "homeassistant.local:8123"}, "url must be"},
		"url with only a scheme":         {map[string]any{"url": "http://"}, "url must be"},
		"url with only a port":           {map[string]any{"url": "http://:8123"}, "url must be"},
		"url with an empty port":         {map[string]any{"url": "http://192.0.2.10:"}, "url must be"},
		"url with port 0":                {map[string]any{"url": "http://192.0.2.10:0"}, "url must be"},
		"url with port 70000":            {map[string]any{"url": "http://192.0.2.10:70000"}, "url must be"},
		"url with a port that is a name": {map[string]any{"url": "http://192.0.2.10:http"}, "url must be"},
		"ftp":                            {map[string]any{"url": "ftp://192.0.2.10"}, "url must be"},
		"ws":                             {map[string]any{"url": "ws://192.0.2.10:8123"}, "url must be"},
		"file":                           {map[string]any{"url": "file:///etc/passwd"}, "url must be"},
		"url with the api path":          {map[string]any{"url": "http://192.0.2.10:8123/api"}, "url must be"},
		"url with a states path":         {map[string]any{"url": "http://192.0.2.10:8123/api/states/"}, "url must be"},
		"url with a service path":        {map[string]any{"url": "http://192.0.2.10:8123/api/services/switch/turn_off"}, "url must be"},
		"url with a path":                {map[string]any{"url": "http://192.0.2.10:8123/ha"}, "url must be"},
		"url with two slashes":           {map[string]any{"url": "http://192.0.2.10:8123//"}, "url must be"},
		"url with a dot path":            {map[string]any{"url": "http://192.0.2.10:8123/."}, "url must be"},
		"url with an escaped path":       {map[string]any{"url": "http://192.0.2.10:8123/%2e%2e"}, "url must be"},
		"url with a query":               {map[string]any{"url": "http://192.0.2.10:8123?x=1"}, "url must be"},
		"url with a query after a slash": {map[string]any{"url": "http://192.0.2.10:8123/?x=1"}, "url must be"},
		"url with an empty query":        {map[string]any{"url": "http://192.0.2.10:8123?"}, "url must be"},
		"url with a fragment":            {map[string]any{"url": "http://192.0.2.10:8123#x"}, "url must be"},
		"url with an empty fragment":     {map[string]any{"url": "http://192.0.2.10:8123/#"}, "url must be"},
		"url with a user":                {map[string]any{"url": "http://fairy@192.0.2.10:8123"}, "url must be"},
		"url with user and password":     {map[string]any{"url": "http://fairy:" + secretInURL + "@192.0.2.10:8123"}, "url must be"},
		"url with an empty user":         {map[string]any{"url": "http://@192.0.2.10:8123"}, "url must be"},
		"url with a backslash":           {map[string]any{"url": "http://192.0.2.10:8123\\api"}, "url must be"},
		"url with a space":               {map[string]any{"url": "http://192.0.2.10:8123 "}, "url must be"},
		"url with a line break":          {map[string]any{"url": "http://192.0.2.10:8123\n"}, "url must be"},
		"url that is opaque":             {map[string]any{"url": "http:192.0.2.10"}, "url must be"},
		// entity: a sensor's id, and nothing that is not part of an id
		"entity missing":          {map[string]any{"entity": nil}, "entity must be"},
		"entity empty":            {map[string]any{"entity": ""}, "entity must be"},
		"a switch":                {map[string]any{"entity": "switch.x"}, "entity must be"},
		"a light":                 {map[string]any{"entity": "light.x"}, "entity must be"},
		"a lock":                  {map[string]any{"entity": "lock.front_door"}, "entity must be"},
		"a binary sensor":         {map[string]any{"entity": "binary_sensor.x"}, "entity must be"},
		"capitals":                {map[string]any{"entity": "sensor.X"}, "entity must be"},
		"capitals in the domain":  {map[string]any{"entity": "Sensor.x"}, "entity must be"},
		"path traversal":          {map[string]any{"entity": "sensor.a/../b"}, "entity must be"},
		"traversal to a service":  {map[string]any{"entity": "sensor.a/../../services/switch/turn_off"}, "entity must be"},
		"traversal before the id": {map[string]any{"entity": "../states/sensor.a"}, "entity must be"},
		"an escaped slash":        {map[string]any{"entity": "sensor.a%2f..%2fb"}, "entity must be"},
		"a query":                 {map[string]any{"entity": "sensor.a?x=1"}, "entity must be"},
		"a fragment":              {map[string]any{"entity": "sensor.a#x"}, "entity must be"},
		"only the domain":         {map[string]any{"entity": "sensor."}, "entity must be"},
		"no domain":               {map[string]any{"entity": "desk_plug_power"}, "entity must be"},
		"no dot":                  {map[string]any{"entity": "sensor_desk_plug_power"}, "entity must be"},
		"two dots":                {map[string]any{"entity": "sensor.a.b"}, "entity must be"},
		"a dash":                  {map[string]any{"entity": "sensor.desk-plug"}, "entity must be"},
		"a space":                 {map[string]any{"entity": "sensor.desk plug"}, "entity must be"},
		"a space before":          {map[string]any{"entity": " sensor.a"}, "entity must be"},
		"a line break after":      {map[string]any{"entity": "sensor.a\n"}, "entity must be"},
		"a line break inside":     {map[string]any{"entity": "sensor.a\nswitch.b"}, "entity must be"},
		"a switch after a sensor": {map[string]any{"entity": "sensor.a,switch.b"}, "entity must be"},
		"not ASCII":               {map[string]any{"entity": "sensor.küche"}, "entity must be"},
		"a NUL":                   {map[string]any{"entity": "sensor.a\x00"}, "entity must be"},
		"the whole list":          {map[string]any{"entity": "*"}, "entity must be"},
		// token_env: a variable's name
		"token_env missing":            {map[string]any{"token_env": nil}, "token_env must be"},
		"token_env empty":              {map[string]any{"token_env": ""}, "token_env must be"},
		"token_env with a dash":        {map[string]any{"token_env": "HA-TOKEN"}, "token_env must be"},
		"token_env with a digit first": {map[string]any{"token_env": "1HA"}, "token_env must be"},
		"token_env with an assignment": {map[string]any{"token_env": "HA_TOKEN=x"}, "token_env must be"},
		"the token instead of a name":  {map[string]any{"token_env": fakeHAToken() + ".part.two"}, "token_env must be"},
		"token_env far too long":       {map[string]any{"token_env": strings.Repeat("A", 129)}, "token_env must be"},
		// token_env: never one of Fairy's own variables (their values would be sent to Home Assistant)
		"the agent's read token":      {map[string]any{"token_env": "FAIRY_AGENT_TOKEN"}, "token_env must not be one of Fairy's own variables"},
		"the agent's control token":   {map[string]any{"token_env": "FAIRY_AGENT_CONTROL_TOKEN"}, "token_env must not be one of Fairy's own variables"},
		"a FAIRY_ name in small":      {map[string]any{"token_env": "fairy_agent_token"}, "token_env must not be one of Fairy's own variables"},
		"a FAIRY_ name in mixed case": {map[string]any{"token_env": "Fairy_Ha_Token"}, "token_env must not be one of Fairy's own variables"},
		"only the prefix":             {map[string]any{"token_env": "FAIRY_"}, "token_env must not be one of Fairy's own variables"},
		// max_age_s
		"max_age_s negative":    {map[string]any{"max_age_s": -1}, "max_age_s must be"},
		"max_age_s over a week": {map[string]any{"max_age_s": 604801}, "max_age_s must be"},
		"max_age_s NaN":         {map[string]any{"max_age_s": math.NaN()}, "max_age_s must be"},
		"max_age_s +Inf":        {map[string]any{"max_age_s": math.Inf(1)}, "max_age_s must be"},
		// the members every type has
		"interval 0.5":   {map[string]any{"interval": 0.5}, "interval must be 1-300"},
		"interval NaN":   {map[string]any{"interval": math.NaN()}, "interval must be 1-300"},
		"id in capitals": {map[string]any{"id": "Desk"}, "id must be"},
		// https only
		"ca_file with http":         {map[string]any{"ca_file": "/etc/fairy-agent/ha.pem"}, "ca_file is only for an https url"},
		"ca_file that is not there": {map[string]any{"url": "https://192.0.2.10:8123", "ca_file": filepath.Join(t.TempDir(), "none.pem")}, "none.pem"},
		// members this type does not have (the decoder is strict), the token written into the file among them
		"a token member":        {map[string]any{"token": fakeHAToken()}, "field token not found"},
		"a password_env member": {map[string]any{"password_env": "HA_PW"}, "field password_env not found"},
		"a username":            {map[string]any{"username": "fairy"}, "field username not found"},
		"verify_tls":            {map[string]any{"verify_tls": false}, "field verify_tls not found"},
		"a method":              {map[string]any{"method": "POST"}, "field method not found"},
		"a path":                {map[string]any{"path": "/api/services/switch/turn_off"}, "field path not found"},
		"entities":              {map[string]any{"entities": []any{"sensor.a", "switch.b"}}, "field entities not found"},
	}
	for name, c := range bad {
		s, err := Build(haEntry("http://192.0.2.10:8123", c.more), nil)
		if err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "desk") && !strings.Contains(err.Error(), "Desk") {
			t.Errorf("%s: %v (want %q, and the entry's id)", name, err, c.want)
		}
		if strings.Contains(err.Error(), fakeHAToken()) || strings.Contains(err.Error(), secretInURL) {
			t.Errorf("%s: the error repeats a secret from the entry: %v", name, err)
		}
	}
	if err := ValidateConfigs([]map[string]any{haEntry("http://192.0.2.10:8123", nil), haEntry("http://192.0.2.11:8123", nil)}); err == nil ||
		!strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("two entries with one id: %v", err)
	}
}

// The address asked is put together from the checked parts only.
func TestHomeAssistantAddress(t *testing.T) {
	for raw, want := range map[string][2]string{
		"http://192.0.2.10:8123":          {"http://192.0.2.10:8123/api/states/sensor.a_1", "192.0.2.10:8123"},
		"http://192.0.2.10:8123/":         {"http://192.0.2.10:8123/api/states/sensor.a_1", "192.0.2.10:8123"},
		"https://ha.example.net":          {"https://ha.example.net/api/states/sensor.a_1", "ha.example.net"},
		"HTTPS://ha.example.net:8443/":    {"https://ha.example.net:8443/api/states/sensor.a_1", "ha.example.net:8443"},
		"http://[fd00::10]:8123":          {"http://[fd00::10]:8123/api/states/sensor.a_1", "[fd00::10]:8123"},
		"http://homeassistant.local:8123": {"http://homeassistant.local:8123/api/states/sensor.a_1", "homeassistant.local:8123"},
	} {
		addr, host, ok := haAddress(raw, "sensor.a_1")
		if !ok || addr != want[0] || host != want[1] {
			t.Errorf("%s: %q %q %v", raw, addr, host, ok)
		}
		if u, err := url.Parse(addr); err != nil || u.Path != "/api/states/sensor.a_1" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			t.Errorf("%s: the address asked is %q", raw, addr)
		}
	}
}

// With an https url Home Assistant's certificate is always checked, against the system's authorities or the
// ca_file. A server that cannot show it never sees the token; there is no member to switch the check off.
func TestHomeAssistantHTTPS(t *testing.T) {
	ha := &fakeHA{entity: "sensor.desk_plug_power"}
	srv := httptest.NewTLSServer(ha)
	defer srv.Close()
	t.Setenv(haTokenEnv, fakeHAToken())
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	// without the ca_file the test server's certificate is nobody's: refused before any request
	s := haSource(t, srv.URL, nil)
	rs, err := s.Read(context.Background(), 3*time.Second)
	if err == nil || len(rs) != 0 || devices.Describe(err) != "tls verification failed" {
		t.Errorf("an unknown certificate: %+v %v", rs, err)
	}
	if reqs := ha.seen(); len(reqs) != 0 {
		t.Errorf("a server with an unknown certificate was sent %d requests", len(reqs))
	}

	// with it: read, and the connection is reused
	s = haSource(t, srv.URL, map[string]any{"ca_file": ca})
	for i := 0; i < 2; i++ {
		rs, err = s.Read(context.Background(), 3*time.Second)
		if err != nil || len(rs) != 1 || *rs[0].Watts != 95.5 {
			t.Fatalf("with the ca_file, read %d: %+v %v", i, rs, err)
		}
	}
	reqs := ha.seen()
	if len(reqs) != 2 || reqs[0].auth != "Bearer "+fakeHAToken() || reqs[0].uri != "/api/states/sensor.desk_plug_power" {
		t.Errorf("%d requests: %v", len(reqs), requestLines(reqs))
	}
	if s.(*homeAssistant).tr == nil || haSource(t, "http://192.0.2.10:8123", nil).(*homeAssistant).tr != nil {
		t.Error("an https source has a transport of its own, an http one uses the shared one")
	}
}

// The token is in no error (its text, its details, what the API shows of it), in no log line and in nothing
// the source says about itself, whatever Home Assistant answers and whatever goes wrong.
func TestHomeAssistantTokenNeverLeaves(t *testing.T) {
	var logged bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	tok := fakeHAToken()
	leaks := func(text string) bool {
		return strings.Contains(text, tok) || strings.Contains(text, url.QueryEscape(tok)) || strings.Contains(text, "Bearer")
	}

	hang := make(chan struct{})
	defer close(hang)
	echo := func(format string, code int) func(w http.ResponseWriter, r *http.Request) { // an answer that repeats the header
		return func(w http.ResponseWriter, r *http.Request) {
			if code != 200 {
				w.WriteHeader(code)
			}
			fmt.Fprintf(w, format, r.Header.Get("Authorization"))
		}
	}
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"401 that repeats the header":   echo(`{"message":"bad token %s"}`, 401),
		"403 that repeats the header":   echo(`{"message":"%s"}`, 403),
		"404 that repeats the header":   echo(`{"message":"%s"}`, 404),
		"500 that repeats the header":   echo(`%s`, 500),
		"not JSON, with the header":     echo(`<html>%s</html>`, 200),
		"the header as the state":       echo(`{"state":"%s","attributes":{"unit_of_measurement":"W"}}`, 200),
		"the header as the unit":        echo(`{"state":"5","attributes":{"unit_of_measurement":"%s"}}`, 200),
		"the header as the class":       echo(`{"state":"5","attributes":{"device_class":"%s"}}`, 200),
		"the header as the time":        echo(`{"state":"5","attributes":{"unit_of_measurement":"W"},"last_reported":"%s"}`, 200),
		"the header as a member's name": echo(`{"%s":1}`, 200),
		"a redirect with the header in its address": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://192.0.2.1/?t="+url.QueryEscape(r.Header.Get("Authorization")), http.StatusFound)
		},
		"connection cut": func(w http.ResponseWriter, _ *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		},
		"no answer in time": func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-hang:
			case <-r.Context().Done():
			}
		},
	}
	check := func(name string, rs []Reading, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error (%s)", name, mustJSON(rs))
			return
		}
		for form, text := range map[string]string{"Error()": err.Error(), "%+v": fmt.Sprintf("%+v", err), "%#v": fmt.Sprintf("%#v", err),
			"Describe": devices.Describe(err)} {
			if leaks(text) {
				t.Errorf("%s: %s shows the token or the header: %s", name, form, text)
			}
		}
		for e := err; e != nil; e = unwrap(e) {
			if _, ok := e.(*url.Error); ok {
				t.Errorf("%s: a *url.Error is inside the returned error", name)
			}
		}
	}
	for name, h := range cases {
		_, srv := startHA(t, h)
		s := haSource(t, srv.URL, map[string]any{"max_age_s": 60})
		for i := 0; i < 2; i++ {
			rs, err := s.Read(context.Background(), 300*time.Millisecond)
			check(name, rs, err)
		}
		srv.CloseClientConnections()
	}
	// nothing listens
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	t.Setenv(haTokenEnv, tok)
	rs, err := haSource(t, dead, nil).Read(context.Background(), 300*time.Millisecond)
	check("nothing listens", rs, err)

	// a token that cannot be sent as it is (a line break, a space, a letter outside ASCII): refused before any
	// request, by the variable's name
	ha, srv := startHA(t, nil)
	for _, broken := range []string{tok + "\n", tok + "\r\nX-Injected: 1", "two words", tok + "é", "\t" + tok} {
		t.Setenv(haTokenEnv, broken)
		rs, err := haSource(t, srv.URL, nil).Read(context.Background(), time.Second)
		check(fmt.Sprintf("a token with %d bytes that cannot be in a header", len(broken)), rs, err)
		if err != nil && (!strings.Contains(err.Error(), haTokenEnv) || strings.Contains(err.Error(), "two words")) {
			t.Errorf("want the variable's name and not its value: %v", err)
		}
	}
	// no token at all: the error names the variable
	t.Setenv(haTokenEnv, "")
	rs, err = haSource(t, srv.URL, nil).Read(context.Background(), time.Second)
	check("the variable is empty", rs, err)
	if err == nil || devices.Describe(err) != "power source desk: env var "+haTokenEnv+" is missing or shorter than 1 chars" {
		t.Errorf("the variable is empty: %v", err)
	}
	if reqs := ha.seen(); len(reqs) != 0 {
		t.Errorf("%d requests were sent without a usable token", len(reqs))
	}

	// the second lock: an error that is not one of the fixed texts, or holds the token, becomes a fixed word
	t.Setenv(haTokenEnv, tok)
	for name, e := range map[string]error{
		"a url.Error":             &url.Error{Op: "Get", URL: "http://192.0.2.1/api/states/sensor.x", Err: context.DeadlineExceeded},
		"a text with the token":   devices.Errf("odd: %s", tok),
		"a text with the header":  devices.Errf("header Bearer x"),
		"a plain error":           fmt.Errorf("odd: %s", tok),
		"a wrapped unknown error": fmt.Errorf("read: %w", io.ErrUnexpectedEOF),
	} {
		if got := haError(e, tok); got.Error() != "request failed" || leaks(fmt.Sprintf("%#v", got)) {
			t.Errorf("%s: %v", name, got)
		}
	}
	plain := devices.Errf("timeout")
	if got := haError(plain, tok); got != plain {
		t.Error("an ordinary error was replaced:", got)
	}
	if got := haError(devices.Errf("home assistant: the sensor is unavailable"), "a"); got.Error() != "home assistant: the sensor is unavailable" {
		t.Error("a short token made a fixed text unreadable:", got)
	}

	// what the source says about itself: its config and its line for the config check
	s := haSource(t, srv.URL, nil)
	about := mustJSON(s.Info()) + fmt.Sprintf("%+v %#v", s.(Checker).Check(), s)
	if leaks(about) {
		t.Errorf("the source's own description shows the token: %s", about)
	}
	if leaks(logged.String()) {
		t.Errorf("a log line shows the token or the header:\n%s", logged.String())
	}
}

// The config check's line: the host, the sensor and whether the variable is set. Never the token.
func TestHomeAssistantCheck(t *testing.T) {
	t.Setenv(haTokenEnv, fakeHAToken())
	s := haSource(t, "https://ha.example.net:8443/", nil)
	want := Check{ID: "desk", Type: "homeassistant", Scheme: "https", Host: "ha.example.net:8443", Reads: "sensor.desk_plug_power",
		SecretEnv: haTokenEnv, SecretSet: true}
	if got := s.(Checker).Check(); got != want {
		t.Errorf("%+v", got)
	}
	t.Setenv(haTokenEnv, "")
	if got := s.(Checker).Check(); got.SecretSet || got.SecretEnv != haTokenEnv {
		t.Errorf("the variable is empty: %+v", got)
	}
	for _, typ := range []map[string]any{{"id": "p", "type": "tasmota", "url": "http://192.0.2.1"}, {"id": "p", "type": "shelly", "url": "http://192.0.2.1"}} {
		if s, err := Build(typ, nil); err != nil {
			t.Fatal(err)
		} else if _, ok := s.(Checker); ok {
			t.Errorf("%v has a Check: the config check's lines would change for it", typ["type"])
		}
	}
}
