package helper

// The text of Windows' shutdown notice as the helper makes it: both ways (a power part that remembers who
// asked and builds the text itself, and one that is handed the text), a requester's hyphen is shown as
// U+2011, and "by" in the status and in the audit log stays the name as it was sent.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

type noticeExec struct{ notices []string }

func (e *noticeExec) Schedule(_ string, _ time.Duration, message string) error {
	e.notices = append(e.notices, message)
	return nil
}
func (e *noticeExec) Cancel() error            { return nil }
func (e *noticeExec) CanSleep() (bool, string) { return true, "" }

func TestHelperNoticeForARequesterWithAHyphen(t *testing.T) {
	const frame = `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test-admin"}`
	const want = "Fairy: shutdown requested by test‑admin in 60 seconds."
	for name, wrap := range map[string]func(agent.PowerExec) agent.PowerExec{
		"a power part that remembers (as on Windows)": func(e agent.PowerExec) agent.PowerExec { return agent.RememberPower(e, nil, nil, nil) },
		"a power part that is handed the text":        func(e agent.PowerExec) agent.PowerExec { return e },
	} {
		windows, audit := &noticeExec{}, &bytes.Buffer{}
		srv := New(Parts{Power: wrap(windows), Audit: slog.New(slog.NewTextHandler(audit, nil))})
		if resp := srv.Handle(context.Background(), "c", []byte(frame)); resp.Status != 200 {
			t.Fatalf("%s: %+v", name, resp)
		}
		if len(windows.notices) != 1 || windows.notices[0] != want {
			t.Errorf("%s: Windows was handed %q, want %q", name, windows.notices, want)
		}
		if l := audit.String(); !strings.Contains(l, "by=test-admin") || strings.Contains(l, "‑") {
			t.Errorf("%s: the audit log:\n%s", name, l)
		}
		resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"status"}`))
		var st proto.StatusData
		if err := json.Unmarshal(resp.Data, &st); err != nil {
			t.Fatal(err)
		}
		if st.Power != nil && st.Power.By != "test-admin" {
			t.Errorf("%s: by in the helper's status: %q", name, st.Power.By)
		}
		if _, remembers := wrap(windows).(interface{ PendingAction() (agent.Pending, bool) }); remembers && st.Power == nil {
			t.Errorf("%s: nothing pending in the helper's status", name)
		}
	}
}
