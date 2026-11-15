package power

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// `sockets:` on a homeassistant entry (PLUGS-DESIGN.md 3.2): decoded, checked, handed on, and never asked of
// Home Assistant by this type.

func socket(id, name, entity string) map[string]any {
	s := map[string]any{"id": id, "switch_entity": entity}
	if name != "" {
		s["name"] = name
	}
	return s
}

func TestHomeAssistantSockets(t *testing.T) {
	// none: an entry from before sockets
	s := haSource(t, "http://192.0.2.10:8123", nil)
	sk, ok := s.(Socketed)
	if !ok {
		t.Fatal("a homeassistant source does not hand sockets on")
	}
	if got := sk.Sockets(); len(got) != 0 {
		t.Fatalf("an entry without sockets has %v", got)
	}
	if got := haSource(t, "http://192.0.2.10:8123", map[string]any{"sockets": []any{}}).(Socketed).Sockets(); len(got) != 0 {
		t.Fatalf("an entry with an empty list has %v", got)
	}
	// a powerbar: in the entry's order, a socket without a name has its id for one
	s = haSource(t, "http://192.0.2.10:8123", map[string]any{"sockets": []any{
		socket("ch1", "Left monitor", "switch.desk_bar_socket_1"),
		socket("ch2", "", "switch.desk_bar_socket_2"),
		socket("0", "Lamp ☀", "switch.desk_bar_socket_3"),
		socket("usb-ports-of-bar", strings.Repeat("n", MaxHASocketName), "switch.desk_bar_usb"),
	}})
	want := []Socket{{"ch1", "Left monitor", "switch.desk_bar_socket_1"}, {"ch2", "ch2", "switch.desk_bar_socket_2"},
		{"0", "Lamp ☀", "switch.desk_bar_socket_3"}, {"usb-ports-of-bar", strings.Repeat("n", 48), "switch.desk_bar_usb"}}
	got := s.(Socketed).Sockets()
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
	got[0].SwitchEntity = "switch.changed_by_the_caller" // a copy: the source's own list stays
	if again := s.(Socketed).Sockets(); again[0] != want[0] {
		t.Fatalf("the caller changed the source's sockets: %+v", again[0])
	}
	// eight are the most
	var eight []any
	for i := 1; i <= MaxHASockets; i++ {
		eight = append(eight, socket(fmt.Sprintf("s%d", i), "", fmt.Sprintf("switch.bar_%d", i)))
	}
	if n := len(haSource(t, "http://192.0.2.10:8123", map[string]any{"sockets": eight}).(Socketed).Sockets()); n != 8 || MaxHASockets != 8 {
		t.Fatalf("%d sockets", n)
	}
	// no other type has sockets
	for _, raw := range []map[string]any{
		{"id": "shelly-1", "type": "shelly", "url": "http://192.0.2.11", "sockets": []any{socket("ch1", "", "switch.x")}},
		{"id": "tasmota-1", "type": "tasmota", "url": "http://192.0.2.12", "sockets": []any{socket("ch1", "", "switch.x")}},
	} {
		if _, err := Build(raw, nil); err == nil || !strings.Contains(err.Error(), "sockets") {
			t.Errorf("%s with sockets: %v", raw["type"], err)
		}
	}
}

func TestHomeAssistantSocketsAreChecked(t *testing.T) {
	secret := strings.Join([]string{"made", "up", "token", "in", "the", "wrong", "place"}, "-")
	nine := func() []any {
		var l []any
		for i := 1; i <= 9; i++ {
			l = append(l, socket(fmt.Sprintf("s%d", i), "", fmt.Sprintf("switch.bar_%d", i)))
		}
		return l
	}()
	item := func(n int, what string) string {
		return fmt.Sprintf("power source desk: sockets, item %d: %s", n, what)
	}
	const list = "power source desk: sockets: must be a list of sockets, each with id, switch_entity and, if wanted, name, and no other member"
	for name, c := range map[string]struct {
		sockets any
		want    string
	}{
		"nine sockets":             {nine, "power source desk: sockets: more than 8 sockets"},
		"no id":                    {[]any{map[string]any{"switch_entity": "switch.a"}}, item(1, "id must be 1-16 lower-case letters, digits and dashes")},
		"an id of 17 characters":   {[]any{socket("ch1", "", "switch.a"), socket(strings.Repeat("a", 17), "", "switch.b")}, item(2, "id must be")},
		"an id in capitals":        {[]any{socket("CH1", "", "switch.a")}, item(1, "id must be")},
		"an id with a space":       {[]any{socket("ch 1", "", "switch.a")}, item(1, "id must be")},
		"an id with an equals":     {[]any{socket("ch=1", "", "switch.a")}, item(1, "id must be")},
		"an id with a slash":       {[]any{socket("ch/1", "", "switch.a")}, item(1, "id must be")},
		"an id that starts -":      {[]any{socket("-ch1", "", "switch.a")}, item(1, "id must be")},
		"an id with a line break":  {[]any{socket("ch1\n", "", "switch.a")}, item(1, "id must be")},
		"the token as an id":       {[]any{socket(secret, "", "switch.a")}, item(1, "id must be")},
		"the same id twice":        {[]any{socket("ch1", "", "switch.a"), socket("ch1", "", "switch.b")}, "power source desk: sockets: two sockets have the same id"},
		"a name of 49 bytes":       {[]any{socket("ch1", strings.Repeat("n", 49), "switch.a")}, item(1, "name must be at most 48 bytes of text without control characters")},
		"a name of 25 letters ü":   {[]any{socket("ch1", strings.Repeat("ü", 25), "switch.a")}, item(1, "name must be")},
		"a name with a line break": {[]any{socket("ch1", "Channel 1\nplug: switched", "switch.a")}, item(1, "name must be")},
		"a name with an escape":    {[]any{socket("ch1", "Lamp\x1b[2J", "switch.a")}, item(1, "name must be")},
		"a name with a NUL":        {[]any{socket("ch1", "Lamp\x00", "switch.a")}, item(1, "name must be")},
		"a name that is not text":  {[]any{socket("ch1", "Lamp\xff", "switch.a")}, item(1, "name must be")},
		"a name, line separator":   {[]any{socket("ch1", "Lamp x", "switch.a")}, item(1, "name must be")},
		"no switch_entity":         {[]any{map[string]any{"id": "ch1"}}, item(1, "switch_entity must be the entity id of a switch")},
		"a sensor":                 {[]any{socket("ch1", "", "sensor.desk_plug_power")}, item(1, "switch_entity must be")},
		"a light":                  {[]any{socket("ch1", "", "light.desk")}, item(1, "switch_entity must be")},
		"a lock":                   {[]any{socket("ch1", "", "lock.front_door")}, item(1, "switch_entity must be")},
		"a script":                 {[]any{socket("ch1", "", "script.all_off")}, item(1, "switch_entity must be")},
		"a switch in capitals":     {[]any{socket("ch1", "", "switch.Desk")}, item(1, "switch_entity must be")},
		"a switch with a path":     {[]any{socket("ch1", "", "switch.a/../../services/lock/unlock")}, item(1, "switch_entity must be")},
		"a switch with a query":    {[]any{socket("ch1", "", "switch.a?x=1")}, item(1, "switch_entity must be")},
		"a switch with a quote":    {[]any{socket("ch1", "", `switch.a","entity_id":"lock.door`)}, item(1, "switch_entity must be")},
		"two switches in one":      {[]any{socket("ch1", "", "switch.a,switch.b")}, item(1, "switch_entity must be")},
		"all":                      {[]any{socket("ch1", "", "all")}, item(1, "switch_entity must be")},
		"the switch domain alone":  {[]any{socket("ch1", "", "switch.")}, item(1, "switch_entity must be")},
		"the token as the switch":  {[]any{socket("ch1", "", secret)}, item(1, "switch_entity must be")},
		"the same switch twice":    {[]any{socket("ch1", "", "switch.a"), socket("ch2", "", "switch.a")}, "power source desk: sockets: two sockets name the same switch_entity"},
		"a member nobody knows":    {[]any{map[string]any{"id": "ch1", "switch_entity": "switch.a", "toggle": true}}, list},
		"the token as a member":    {[]any{map[string]any{"id": "ch1", "switch_entity": "switch.a", "token": secret}}, list},
		"a url in a socket":        {[]any{map[string]any{"id": "ch1", "switch_entity": "switch.a", "url": "http://192.0.2.99:8123"}}, list},
		"a text for the list":      {secret, list},
		"a mapping for the list":   {map[string]any{"ch1": "switch.a"}, list},
		"a list of texts":          {[]any{"switch.a", "switch.b"}, list},
		"a number for a name":      {[]any{map[string]any{"id": "ch1", "switch_entity": "switch.a", "name": []any{1}}}, list},
	} {
		_, err := Build(haEntry("http://192.0.2.10:8123", map[string]any{"sockets": c.sockets}), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v\nwant an error with %q", name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "192.0.2") || strings.Contains(err.Error(), "switch.a") {
			t.Errorf("%s: the error repeats what was written: %v", name, err)
		}
	}
}

// An entry with sockets reads its watts exactly as one without: the same requests, for sensors only. Nothing
// about a socket is ever asked by this type, and nothing but a GET is ever sent.
func TestHomeAssistantNeverAsksAboutItsSockets(t *testing.T) {
	ha, srv := startHA(t, nil)
	s := haSource(t, srv.URL, map[string]any{"sockets": []any{
		socket("ch1", "Left monitor", "switch.desk_bar_socket_1"), socket("ch2", "", "switch.desk_bar_socket_2")}})
	for i := 0; i < 3; i++ {
		rs, err := s.Read(context.Background(), 2*time.Second)
		if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 95.5 {
			t.Fatalf("read %d: %+v %v", i, rs, err)
		}
	}
	_ = s.(Checker).Check()
	_ = s.(Socketed).Sockets()
	s.Close()
	reqs := ha.seen()
	if len(reqs) != 3 {
		t.Fatalf("%d requests for 3 readings", len(reqs))
	}
	for i, q := range reqs {
		if q.method != http.MethodGet || q.uri != "/api/states/sensor.desk_plug_power" || q.bodyBytes != 0 || strings.Contains(q.uri, "switch") {
			t.Errorf("request %d: %s %s with %d bytes of body", i, q.method, q.uri, q.bodyBytes)
		}
	}
	// the config check's line of the source does not change with sockets (the agent prints its own lines for them)
	plain := haSource(t, srv.URL, nil).(Checker).Check()
	if with := haSource(t, srv.URL, map[string]any{"sockets": []any{socket("ch1", "", "switch.desk_bar_socket_1")}}).(Checker).Check(); with != plain {
		t.Errorf("the check of an entry with sockets is %+v, without %+v", with, plain)
	}
}
