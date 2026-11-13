package power

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

type refusedSays bool

func (e refusedSays) Error() string { return "says" }
func (e refusedSays) Refused() bool { return bool(e) }

// Refused is true only for an error that says so itself, also through a wrapper. Of the source types, only
// homeassistant returns one, and only for Home Assistant's 401 and 403: every other answer and failure is
// asked again at the normal interval.
func TestRefused(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"no error":                        {nil, false},
		"a fixed text":                    {devices.Errf("timeout"), false},
		"http 401 of another device":      {&devices.HTTPStatusError{Code: 401}, false},
		"an error that says no":           {refusedSays(false), false},
		"an error that says yes":          {refusedSays(true), true},
		"wrapped, says yes":               {fmt.Errorf("read: %w", refusedSays(true)), true},
		"wrapped, says no":                {fmt.Errorf("read: %w", refusedSays(false)), false},
		"refusedf":                        {refusedf("the %s was refused", "password"), true},
		"home assistant, 401":             {haError(&devices.HTTPStatusError{Code: 401}, "t"), true},
		"home assistant, 403":             {haError(&devices.HTTPStatusError{Code: 403}, "t"), true},
		"home assistant, 404":             {haError(&devices.HTTPStatusError{Code: 404}, "t"), false},
		"home assistant, 400":             {haError(&devices.HTTPStatusError{Code: 400}, "t"), false},
		"home assistant, 429":             {haError(&devices.HTTPStatusError{Code: 429}, "t"), false},
		"home assistant, 500":             {haError(&devices.HTTPStatusError{Code: 500}, "t"), false},
		"home assistant, a timeout":       {haError(devices.Errf("timeout"), "t"), false},
		"home assistant, an unknown kind": {haError(errors.New("odd"), "t"), false},
	} {
		if got := Refused(c.err); got != c.want {
			t.Errorf("%s: Refused is %v, want %v", name, got, c.want)
		}
	}
	// a refusal is still a text that is safe to show, and nothing else
	err := refusedf("the %s was refused", "password")
	var de *devices.Error
	if err.Error() != "the password was refused" || devices.Describe(err) != "the password was refused" || !errors.As(err, &de) {
		t.Errorf("%v / %q", err, devices.Describe(err))
	}

	for n, want := range map[int]time.Duration{-1: 5 * time.Minute, 0: 5 * time.Minute, 1: 5 * time.Minute, 2: 15 * time.Minute,
		3: time.Hour, 4: time.Hour, 1000: time.Hour} {
		if got := RefusedWait(n); got != want {
			t.Errorf("RefusedWait(%d) is %v, want %v", n, got, want)
		}
	}
}

// Through the real request: the two refusals of a Home Assistant are Refused, with the text the row shows; a
// missing entity, a server error and a token that is not set (no request at all) are not.
func TestHomeAssistantRefusalIsMarked(t *testing.T) {
	for code, want := range map[int]bool{401: true, 403: true, 404: false, 500: false, 429: false} {
		_, srv := startHA(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		_, err := haSource(t, srv.URL, nil).Read(context.Background(), 2*time.Second)
		if err == nil || Refused(err) != want || (want && devices.Describe(err) != "home assistant refused the token") {
			t.Errorf("http %d: %v, Refused %v, want %v", code, err, Refused(err), want)
		}
	}
	ha, srv := startHA(t, nil)
	t.Setenv(haTokenEnv, "")
	if _, err := haSource(t, srv.URL, nil).Read(context.Background(), 2*time.Second); err == nil || Refused(err) || len(ha.seen()) != 0 {
		t.Errorf("no token: %v, Refused %v, %d requests", err, Refused(err), len(ha.seen()))
	}
}
