package agent

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// hostileCollector is the fake PC whose sample is changed before the agent sees it.
type hostileCollector struct {
	*agenttest.Collector
	change func(*collect.Sample)
}

func (c hostileCollector) Sample(ctx context.Context) collect.Sample {
	s := c.Collector.Sample(ctx)
	if c.change != nil {
		c.change(&s)
	}
	return s
}

type gpuList []collect.GPU

func (g gpuList) GPUs() []collect.GPU                       { return g }
func (gpuList) ComputeApps(context.Context) map[int][]int64 { return nil }
func card(name string, watts *float64, temp *float64) collect.GPU {
	return collect.GPU{Name: name, Vendor: "nvidia", PowerW: watts, TempC: temp}
}

// getMetrics asks a new agent's real handler for /metrics and returns the status, the raw body and the body
// as a generic document (the test fails if the body is not valid JSON).
func getMetrics(t *testing.T, c collect.Collector, g GPUSource) (int, []byte, map[string]any) {
	t.Helper()
	a := New(mustParse(t, ""), Tokens{Read: readTok}, Deps{Collector: c, GPU: g, Version: "test"})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+readTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("/metrics is not valid JSON (%v): %.300s", err, body)
	}
	return resp.StatusCode, body, doc
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// M2: the watts of the cards are added up. A card whose watts cannot be a reading (NaN, an infinity, 1e308,
// negative) loses that value in its own row, the total is then unknown, and possible numbers that add up to an
// impossible one give no total either. The answer is 200 and valid JSON in every case; on the unfixed code the
// NaN / Inf cases answered 500 {"error":"internal error"} and the others sent the impossible total.
func TestMetricsGPUWattsSum(t *testing.T) {
	f := collect.P[float64]
	for name, tc := range map[string]struct {
		cards    gpuList
		rowWatts []any // power_w per row, nil = null
		total    any   // power.gpu_w, nil = no total
	}{
		"ordinary":              {gpuList{card("a", f(87.5), f(61)), card("b", f(12.5), nil)}, []any{87.5, 12.5}, 100.0},
		"no watts at all":       {gpuList{card("a", nil, f(50))}, []any{nil}, nil},
		"one without watts":     {gpuList{card("a", f(40), nil), card("b", nil, nil)}, []any{40.0, nil}, 40.0},
		"NaN":                   {gpuList{card("a", f(math.NaN()), nil), card("b", f(40), nil)}, []any{nil, 40.0}, nil},
		"+Inf":                  {gpuList{card("a", f(40), nil), card("b", f(math.Inf(1)), nil)}, []any{40.0, nil}, nil},
		"+Inf and -Inf":         {gpuList{card("a", f(math.Inf(1)), nil), card("b", f(math.Inf(-1)), nil)}, []any{nil, nil}, nil},
		"1e308 twice":           {gpuList{card("a", f(1e308), nil), card("b", f(1e308), nil)}, []any{nil, nil}, nil},
		"negative":              {gpuList{card("a", f(-5), nil), card("b", f(40), nil)}, []any{nil, 40.0}, nil},
		"possible, sum is not":  {gpuList{card("a", f(9e11), nil), card("b", f(9e11), nil)}, []any{9e11, 9e11}, nil},
		"temperature not a num": {gpuList{card("a", f(40), f(math.NaN()))}, []any{40.0}, 40.0},
	} {
		st, body, doc := getMetrics(t, agenttest.NewCollector(), tc.cards)
		if st != 200 {
			t.Errorf("%s: status %d: %.200s", name, st, body)
			continue
		}
		if _, has := doc[DroppedSectionsKey]; has {
			t.Errorf("%s: no section may be dropped for a GPU's watts: %v", name, doc[DroppedSectionsKey])
		}
		rows := doc["gpus"].([]any)
		if len(rows) != len(tc.cards) {
			t.Errorf("%s: %d GPU rows, want %d (a row must stay)", name, len(rows), len(tc.cards))
			continue
		}
		for i, r := range rows {
			row := r.(map[string]any)
			if row["power_w"] != tc.rowWatts[i] || row["name"] != tc.cards[i].Name {
				t.Errorf("%s: row %d = %v, want power_w %v", name, i, row, tc.rowWatts[i])
			}
			if name == "temperature not a num" && row["temp_c"] != nil {
				t.Errorf("%s: temp_c = %v", name, row["temp_c"])
			}
		}
		pw, _ := doc["power"].(map[string]any)
		var total any
		var sources []any
		if pw != nil {
			total, sources = pw["gpu_w"], pw["source"].([]any)
		}
		if total != tc.total || slices.Contains(sources, any("gpu")) != (tc.total != nil) {
			t.Errorf("%s: power = %v, want gpu_w %v", name, pw, tc.total)
		}
	}
}

// M2: one section that cannot be written as JSON no longer fails the whole answer. A list of rows keeps its
// good rows, another section becomes null, "dropped_sections" names them, every other section is untouched and
// every key of the ordinary answer is still there. Unfixed: 500 for each of these samples.
func TestMetricsSurvivesAnUnwritableSection(t *testing.T) {
	nan, inf := math.NaN(), math.Inf(1)
	_, _, ordinary := getMetrics(t, agenttest.NewCollector(), agenttest.GPU{})
	if _, has := ordinary[DroppedSectionsKey]; has {
		t.Fatal("an ordinary answer must not have ", DroppedSectionsKey)
	}
	for name, tc := range map[string]struct {
		change  func(*collect.Sample)
		dropped []any
		check   func(t *testing.T, doc map[string]any)
	}{
		"one temperature is NaN": {
			func(s *collect.Sample) {
				s.Temps = []collect.Temp{{Sensor: "a", Current: 41}, {Sensor: "b", Current: nan}, {Sensor: "c", Current: 43}}
			},
			[]any{"temps"},
			func(t *testing.T, doc map[string]any) {
				temps := doc["temps"].([]any)
				if len(temps) != 2 || temps[0].(map[string]any)["sensor"] != "a" || temps[1].(map[string]any)["current"] != 43.0 {
					t.Error("the two good sensors must stay:", temps)
				}
			}},
		"every fan is Inf, a voltage too": {
			func(s *collect.Sample) {
				s.Fans = []collect.Fan{{Name: "f1", RPM: inf}, {Name: "f2", RPM: -inf}}
				s.Voltages = []collect.Voltage{{Name: "12V", Volts: 12.1}, {Name: "5V", Volts: inf}}
			},
			[]any{"fans", "voltages"},
			func(t *testing.T, doc map[string]any) {
				if fans, ok := doc["fans"].([]any); !ok || len(fans) != 0 {
					t.Error("fans must be an empty list:", doc["fans"])
				}
				if v := doc["voltages"].([]any); len(v) != 1 || v[0].(map[string]any)["name"] != "12V" {
					t.Error("voltages:", v)
				}
			}},
		"CPU percent is NaN": {
			func(s *collect.Sample) { s.CPUPercent = &nan },
			[]any{"cpu"},
			func(t *testing.T, doc map[string]any) {
				if v, has := doc["cpu"]; !has || v != nil {
					t.Error("cpu must be null:", v)
				}
			}},
		"load average and CPU watts": {
			func(s *collect.Sample) {
				s.LoadAvg = []float64{0.5, nan, 0.25}
				s.Power.CPUPackageW = &inf
			},
			[]any{"load_avg", "power"},
			func(t *testing.T, doc map[string]any) {
				// 1, 5 and 15 minutes: a list of plain values is never shortened (the rest would change places)
				if v, has := doc["load_avg"]; !has || v != nil {
					t.Error("load_avg must be null:", v)
				}
				if v, has := doc["power"]; !has || v != nil {
					t.Error("power must be null:", v)
				}
			}},
	} {
		st, body, doc := getMetrics(t, hostileCollector{agenttest.NewCollector(), tc.change}, agenttest.GPU{})
		if st != 200 {
			t.Errorf("%s: status %d: %.200s", name, st, body)
			continue
		}
		if !reflect.DeepEqual(doc[DroppedSectionsKey], tc.dropped) {
			t.Errorf("%s: %s = %v, want %v", name, DroppedSectionsKey, doc[DroppedSectionsKey], tc.dropped)
		}
		tc.check(t, doc)
		// additive: every key of the ordinary answer is there, and nothing but the one new key was added
		// ("power" is only sent when it holds a reading, which the hostile CPU watts are)
		want := append(keysOf(ordinary), DroppedSectionsKey)
		if name == "load average and CPU watts" && !slices.Contains(want, "power") {
			want = append(want, "power")
		}
		sort.Strings(want)
		if got := keysOf(doc); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: keys %v, want %v", name, got, want)
		}
		// sections that were not named are what they are in an ordinary answer
		for _, k := range []string{"memory", "disks", "gpus", "platform", "features", "hostname", "agent_version", "uptime_s"} {
			if !reflect.DeepEqual(doc[k], ordinary[k]) {
				t.Errorf("%s: section %s changed: %v", name, k, doc[k])
			}
		}
	}
}

// The fallback itself: values of any kind, and never an error for the caller.
func TestEncodeMetrics(t *testing.T) {
	good := map[string]any{"a": 1, "list": []int{1, 2}, "obj": map[string]any{"x": "y"}, "none": nil}
	b, dropped := encodeMetrics(good)
	if want, _ := json.Marshal(good); string(b) != string(want) || dropped != nil {
		t.Fatalf("an answer that can be written must be written as before: %s %v", b, dropped)
	}
	b, dropped = encodeMetrics(map[string]any{
		"a": 1, "scalar": math.NaN(), "list": []float64{1, math.Inf(-1), 3}, "rows": []map[string]any{{"w": math.NaN()}, {"w": 2.5}},
		"obj": map[string]any{"x": math.NaN()}, "fn": func() {}, "array": [2]float64{math.NaN(), 7}, "none": nil,
		"ptr": &[]float64{math.NaN()},
	})
	const want = `{"a":1,"array":null,"dropped_sections":["array","fn","list","obj","ptr","rows","scalar"],"fn":null,"list":null,` +
		`"none":null,"obj":null,"ptr":null,"rows":[{"w":2.5}],"scalar":null}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if len(dropped) != 7 || !sort.StringsAreSorted(dropped) {
		t.Fatal(dropped)
	}
}
