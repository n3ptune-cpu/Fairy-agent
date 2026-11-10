package redact

// The join code of the panel's Add host must not show up in a process list: `fairy-agent join --code CODE` and
// the installer's own command line (install.sh --join CODE, install.ps1 -Join CODE) carry it while they run.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// the places a join code stands in; %s is the code
var joinForms = []string{
	"/usr/local/bin/fairy-agent join --code %s --panel 100.64.0.1 --self-update",
	"fairy-agent join --code=%s --panel 100.64.0.1",
	"sudo ./fairy-agent join -code %s --panel 100.64.0.1 --pair-v2",
	`C:\Program Files\Fairy\fairy-agent.exe join --code %s --panel 100.64.0.1`,
	"sh /tmp/install.sh --join %s --panel 100.64.0.1 --power-control",
	"bash -s -- --join %s --panel 100.64.0.1",
	"powershell -ExecutionPolicy Bypass -File install.ps1 -Join %s -PanelAddress 100.64.0.1",
	"env FAIRY_JOIN_CODE=%s /usr/local/bin/fairy-agent join --code-stdin --panel 100.64.0.1",
	"some-other-tool --anything %s",
	"%s",
}

func TestJoinCodeIsHidden(t *testing.T) {
	for i := 0; i < 200; i++ {
		raw, err := enroll.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		raw, err = enroll.Normalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		grouped := enroll.Group(raw)
		// as the panel shows it, without dashes, both in small letters, and with the dashes somewhere else
		spellings := []string{grouped, raw, strings.ToLower(grouped), strings.ToLower(raw), raw[:8] + "-" + raw[8:20] + "-" + raw[20:]}
		for _, code := range spellings {
			for _, form := range joinForms {
				cmd := fmt.Sprintf(form, code)
				for how, out := range map[string]string{"Cmdline": Cmdline(cmd, 300), "Args": Args(strings.Fields(cmd), 300)} {
					if strings.Contains(out, code) || strings.Contains(strings.ToUpper(out), raw[:12]) || !strings.Contains(out, mask) {
						t.Fatalf("%s: %q -> %q", how, cmd, out)
					}
					if again := Cmdline(out, 300); again != out {
						t.Fatalf("%s twice: %q -> %q", how, out, again)
					}
				}
			}
		}
	}
}

func TestJoinCodeExactResults(t *testing.T) {
	const code = "MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OBYX-E43U"
	for in, want := range map[string]string{
		"fairy-agent join --code " + code + " --panel 100.64.0.1 --wol": "fairy-agent join --code *** --panel 100.64.0.1 --wol",
		"fairy-agent join --code=" + code + " --panel 100.64.0.1":       "fairy-agent join --code=*** --panel 100.64.0.1",
		"sh install.sh --join " + code + " --panel 100.64.0.1":          "sh install.sh --join *** --panel 100.64.0.1",
		"FAIRY_JOIN_CODE=" + code + " fairy-agent join --code-stdin":    "FAIRY_JOIN_CODE=*** fairy-agent join --code-stdin",
		"echo '" + code + "' | fairy-agent join --code-stdin":           "echo '***' | fairy-agent join --code-stdin",
		// a code that is not one (mistyped, cut off) is still hidden where the option or the variable names it
		"fairy-agent join --code MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OBYX --panel 100.64.0.1": "fairy-agent join --code *** --panel 100.64.0.1",
		"fairy-agent join --code=MFRG1GZDF --panel 100.64.0.1":                          "fairy-agent join --code=*** --panel 100.64.0.1",
		"FAIRY_JOIN_CODE=not-a-code fairy-agent join":                                   "FAIRY_JOIN_CODE=*** fairy-agent join",
	} {
		if got := Cmdline(in, 300); got != want {
			t.Errorf("Cmdline(%q)\n got %q\nwant %q", in, got, want)
		}
		if got := Args(strings.Fields(in), 300); got != want {
			t.Errorf("Args(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	// as arguments the value is hidden as a whole, also when it was typed with blanks
	spaced := strings.ReplaceAll(code, "-", " ")
	for _, args := range [][]string{
		{"fairy-agent", "join", "--code", spaced, "--panel", "100.64.0.1"},
		{"fairy-agent", "join", "--code=" + spaced, "--panel", "100.64.0.1"},
		{"env", "FAIRY_JOIN_CODE=" + spaced, "fairy-agent", "join"},
	} {
		if got := Args(args, 300); strings.Contains(got, "MFRG") || strings.Contains(got, "E43U") || !strings.Contains(got, mask) {
			t.Errorf("Args(%q) = %q", args, got)
		}
	}
}

// What only looks a little like a join code stays as it is.
func TestJoinCodeLookAlikesStay(t *testing.T) {
	for _, cmd := range []string{
		"fairy-agent join --code-stdin --panel 100.64.0.1 --pair-v2",
		"fairy-agent join --panel 100.64.0.1 --self-update",
		"fairy-agent pair-status",
		"python3 app.py --code 42 --verbose",
		"app --code=E1234 --exit-code 3",
		"FAIRY_JOIN_CODE= fairy-agent join",
		"uuidgen 550e8400-e29b-41d4-a716-446655440000",
		"sha256sum 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"md5 d41d8cd98f00b204e9800998ecf8427e",
		"apt-get install --no-install-recommends --allow-change-held-packages qemu-guest-agent",
		"/usr/lib/systemd/systemd-timesyncd --some-very-long-option-name-with-many-words=1",
		"license ABCD-EFGH-IJKL-MNOP",
		"serial ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCD", // 36 characters: longer than a join code
		"serial ABCDEFGHIJKLMNOPQRSTUVWXYZ2345",       // 30
		"docker run --name my-app-with-a-long-name-here-ok registry.example.com/team/image:tag",
		"java -cp /opt/app/lib/* com.example.VeryLongApplicationMainClassName",
	} {
		if got := Cmdline(cmd, 300); got != cmd {
			t.Errorf("Cmdline changed %q\n to %q", cmd, got)
		}
		if got := Args(strings.Fields(cmd), 300); got != cmd {
			t.Errorf("Args changed %q\n to %q", cmd, got)
		}
	}
}
