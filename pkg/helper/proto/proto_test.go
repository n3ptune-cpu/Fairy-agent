package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestDecodeRequestAccepts(t *testing.T) {
	for _, s := range []string{
		`{"v":1,"verb":"ping"}`,
		`{"v":1,"verb":"status"}`,
		`{"v":1,"verb":"coretemp_read"}`,
		`{"v":1,"verb":"ipmi_sensors"}`,
		`{"v":1,"verb":"fan_status"}`,
		`{"v":1,"verb":"fan_set","zone":0,"percent":30}`,
		`{"v":1,"verb":"fan_set","zone":1,"percent":100,"by":"panel 100.64.0.2"}`,
		`{"v":1,"verb":"fan_mode","mode":"full"}`,
		`{"v":1,"verb":"fan_mode","mode":"heavyio","by":"x"}`,
		`{"v":1,"verb":"fan_auto"}`,
		`{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"panel 100.64.0.2"}`,
		`{"v":1,"verb":"power","action":"sleep","delay_s":10}`,
		`{"v":1,"verb":"power","action":"cancel"}`,
		`{"v":1,"verb":"apply_update","by":"self-update"}`,
	} {
		if _, err := DecodeRequest([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestDecodeRequestRejects(t *testing.T) {
	cases := []struct{ in, code string }{
		{`{"v":1,"verb":"exec"}`, CodeUnknownVerb},
		{`{"v":1,"verb":"shell","cmd":"whoami"}`, CodeBadRequest},
		{`{"v":1,"verb":""}`, CodeUnknownVerb},
		{`{"v":2,"verb":"ping"}`, CodeBadRequest},
		{`{"verb":"ping"}`, CodeBadRequest},
		{`{"v":1,"verb":"ping","path":"C:\\x"}`, CodeBadRequest},
		{`{"v":1,"verb":"ping","zone":0}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_status","by":"x"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":29}`, CodeBadRequest}, // the 30 % floor
		{`{"v":1,"verb":"fan_set","zone":0,"percent":0}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":-5}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":101}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":2,"percent":50}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":50.5}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":"50"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":50,"mode":"full"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_mode","mode":"pue"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_mode","mode":"FULL"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_mode"}`, CodeBadRequest},
		{`{"v":1,"verb":"fan_auto","mode":"standard"}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"hibernate","delay_s":60}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown"}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":9}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":86401}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"cancel","delay_s":60}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"a;b"}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"` + strings.Repeat("a", 65) + `"}`, CodeBadRequest},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":""}`, CodeBadRequest},
		{`{"v":1,"verb":"ping"}{"v":1,"verb":"ping"}`, CodeBadRequest},
		{`{"v":1,"verb":"ping"} x`, CodeBadRequest},
		{`[]`, CodeBadRequest},
		{`null`, CodeBadRequest},
		{``, CodeBadRequest},
		{`{"v":1,"verb":"ping","padding":"` + strings.Repeat("x", MaxRequest) + `"}`, CodeTooLarge},
	}
	for _, c := range cases {
		_, err := DecodeRequest([]byte(c.in))
		if err == nil {
			t.Errorf("%.80s: accepted", c.in)
			continue
		}
		if code(err) != c.code {
			t.Errorf("%.80s: code %q (%v), want %q", c.in, code(err), err, c.code)
		}
	}
}

func TestEncodeRequestValidates(t *testing.T) {
	p := 29
	z := 0
	if _, err := EncodeRequest(Request{Verb: VerbFanSet, Zone: &z, Percent: &p}); code(err) != CodeBadRequest {
		t.Fatal("encoded a duty below 30 %")
	}
	b, err := EncodeRequest(Request{Verb: VerbPing})
	if err != nil || string(b) != `{"v":1,"verb":"ping"}` {
		t.Fatal(string(b), err)
	}
}

func TestEveryVerbHasASchema(t *testing.T) {
	want := []string{"apply_update", "challenge", "coretemp_read", "fan_auto", "fan_mode", "fan_set", "fan_status", "ipmi_sensors", "ping", "power", "status", "trust_init"}
	if got := strings.Join(Verbs(), ","); got != strings.Join(want, ",") {
		t.Fatal(got)
	}
	for _, v := range Verbs() {
		if Control(v) != (v == "fan_set" || v == "fan_mode" || v == "fan_auto" || v == "power" || v == "apply_update" || v == "challenge" || v == "trust_init") {
			t.Error("control class of", v)
		}
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"v":1,"verb":"ping"}`), MaxRequest); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFrame(&buf, MaxRequest)
	if err != nil || string(b) != `{"v":1,"verb":"ping"}` {
		t.Fatal(string(b), err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxRequest+1), MaxRequest); err == nil {
		t.Fatal("wrote an oversized frame")
	}
	// an oversized length prefix is refused before anything is allocated or read
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 1<<31)
	r := bytes.NewReader(append(hdr[:], 'x'))
	if _, err := ReadFrame(r, MaxRequest); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatal("read past the header")
	}
	// truncated
	binary.BigEndian.PutUint32(hdr[:], 10)
	if _, err := ReadFrame(bytes.NewReader(append(hdr[:], 'a', 'b')), MaxRequest); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), MaxRequest); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestResponses(t *testing.T) {
	for c, st := range map[string]int{CodeBadRequest: 400, CodeUnknownVerb: 400, CodeTooLarge: 413, CodeRateLimited: 429,
		CodeDisabled: 404, CodeUnavailable: 503, CodeDenied: 503, CodeFailed: 500} {
		if r := Fail(c, "x"); r.Status != st || r.Code != c {
			t.Error(c, r)
		}
	}
	r, err := DecodeResponse([]byte(`{"status":200,"data":{"pong":true}}`))
	if err != nil || r.Status != 200 || string(r.Data) != `{"pong":true}` {
		t.Fatal(r, err)
	}
	for _, bad := range []string{`{"status":0}`, `{"status":900}`, `nope`, ``} {
		if _, err := DecodeResponse([]byte(bad)); err == nil {
			t.Error("accepted", bad)
		}
	}
	if _, err := DecodeResponse(make([]byte, MaxResponse+1)); err == nil {
		t.Error("accepted an oversized answer")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(3, 2, time.Minute)
	l.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow(VerbPing) {
			t.Fatal("read", i)
		}
	}
	if l.Allow(VerbStatus) {
		t.Fatal("4th read allowed")
	}
	// changes have their own, smaller budget
	if !l.Allow(VerbFanSet) || !l.Allow(VerbPower) || l.Allow(VerbFanMode) {
		t.Fatal("change budget")
	}
	now = now.Add(time.Minute)
	if !l.Allow(VerbPing) || !l.Allow(VerbFanAuto) {
		t.Fatal("window did not slide")
	}
}

// TestLimiterClasses (audit 5, r1-a2-03): challenges, and the two requests that only make things safer (power
// cancel, fan_auto), are counted apart from the changes and from each other.
func TestLimiterClasses(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(3, 2, time.Minute)
	l.Now = func() time.Time { return now }
	cancel, shutdown := "cancel", "shutdown"
	for i := 0; i < ChallengesPerMinute; i++ {
		if !l.AllowRequest(Request{Verb: VerbChallenge}) {
			t.Fatal("challenge", i)
		}
	}
	if l.AllowRequest(Request{Verb: VerbChallenge}) {
		t.Fatal("one challenge too many was allowed")
	}
	if !l.AllowRequest(Request{Verb: VerbPower, Action: &shutdown}) || !l.AllowRequest(Request{Verb: VerbFanSet}) ||
		l.AllowRequest(Request{Verb: VerbTrustInit}) || l.AllowRequest(Request{Verb: VerbApplyUpdate}) {
		t.Fatal("change budget")
	}
	for i := 0; i < SafePerMinute; i++ {
		req := Request{Verb: VerbPower, Action: &cancel}
		if i%2 == 1 {
			req = Request{Verb: VerbFanAuto}
		}
		if !l.AllowRequest(req) {
			t.Fatal("cancel / fan_auto", i)
		}
	}
	if l.AllowRequest(Request{Verb: VerbPower, Action: &cancel}) || l.AllowRequest(Request{Verb: VerbFanAuto}) {
		t.Fatal("one safe request too many was allowed")
	}
	if !l.AllowRequest(Request{Verb: VerbStatus}) {
		t.Fatal("a read was kept out by the others")
	}
}

// TestDecodeRequestRefusesAMemberTwice (audit 5, r2-a1-06): the comment said "no duplicate", and encoding/json
// took the last of two members of one name: `{"verb":"ping", ..., "verb":"power"}` was a power request. A frame
// with a name twice in one object, at any depth and in any letter case, is refused, in both frame versions.
func TestDecodeRequestRefusesAMemberTwice(t *testing.T) {
	entry := `{"machine_id":"mmmmmmmmmmmmmmmmmmmmmm","challenge":"` + strings.Repeat("A", 43) + `","request":"apply_update"}`
	for _, c := range []struct {
		in string
		v3 bool
	}{
		{`{"v":1,"verb":"ping","verb":"power","action":"shutdown","delay_s":60}`, false},
		{`{"v":1,"verb":"power","action":"cancel","action":"shutdown","delay_s":60}`, false},
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":86400,"delay_s":60}`, false},
		{`{"v":1,"verb":"fan_set","zone":0,"percent":30,"PERCENT":100}`, false},
		{`{"v":1,"V":1,"verb":"ping"}`, false},
		{`{"v":3,"verb":"challenge","for":"power","action":"sleep","action":"shutdown","delay_s":60}`, true},
		{`{"v":3,"verb":"challenge","for":"fan_mode","for":"power","action":"shutdown","delay_s":60}`, true},
		{`{"v":3,"verb":"apply_update","approval":{"token":"a.b.c","token":"d.e.f","entries":[` + entry + `]}}`, true},
		{`{"v":3,"verb":"apply_update","approval":{"token":"a.b.c","entries":[` + strings.Replace(entry, `"request":"apply_update"`, `"request":"x","request":"apply_update"`, 1) + `]}}`, true},
		{"{\"v\":1,\"verb\":\"power\",\"action\":\"cancel\",\"by\":\"\xff\"}", false}, // not UTF-8
	} {
		decode := DecodeRequest
		if c.v3 {
			decode = DecodeRequestV3
		}
		_, err := decode([]byte(c.in))
		if err == nil || code(err) != CodeBadRequest {
			t.Errorf("%.90s: %v, want %s", c.in, err, CodeBadRequest)
		}
	}
	// the same frames with each member once are requests
	for _, c := range []struct {
		in string
		v3 bool
	}{
		{`{"v":1,"verb":"power","action":"shutdown","delay_s":60}`, false},
		{`{"v":3,"verb":"challenge","for":"power","action":"shutdown","delay_s":60}`, true},
		{`{"v":3,"verb":"apply_update","approval":{"token":"a.b.c","entries":[` + entry + `]}}`, true},
	} {
		decode := DecodeRequest
		if c.v3 {
			decode = DecodeRequestV3
		}
		if _, err := decode([]byte(c.in)); err != nil {
			t.Errorf("%.90s: %v", c.in, err)
		}
	}
}
