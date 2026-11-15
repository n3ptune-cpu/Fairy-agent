package agent

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs"
)

// envNamesFold says whether this system takes two names of environment variables that differ in letter case
// only as one variable. Windows does; every other system has two variables then (tests put their own here).
var envNamesFold = runtime.GOOS == "windows"

// sameEnvName says whether a and b name one environment variable on this system.
func sameEnvName(a, b string) bool {
	if envNamesFold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// PlugReport is what this machine's config says about its Home Assistant and its sockets, in words: the lines
// check-config prints after its "config OK", and what the agent writes to its log when it starts. It is made
// from the config alone. The token is not read, shown or tried, and Home Assistant is not asked anything.
type PlugReport struct {
	// Lines: one for the home_assistant block, one for each socket, one for the sockets that are never switched.
	Lines []string
	// Notes: what loads and will not do what its owner may expect (check-config prints each after "note: ", the
	// start log has each as a warning).
	Notes []string
	// Remarks: what is worth saying once and is nothing to worry about (check-config prints each after "note: "
	// as well, after the Notes; the start log has each as an info line, not a warning).
	Remarks []string
	// Sockets is how many sockets the config has, Switchable how many of them a switch request is not refused
	// for by the config, Never the entity ids of feeds_self.
	Sockets, Switchable int
	Never               []string
}

// PlugReport describes p, the keeper Config.NewPlugs built from this config (nil: the report is empty).
// approvalState is what is known of the passkey check on this machine: api.ApprovalOff, api.ApprovalRequired,
// api.ApprovalBroken, or "" when it cannot be told (then nothing is said about it).
func (c *Config) PlugReport(p *plugs.Plugs, approvalState string) PlugReport {
	var rep PlugReport
	if p == nil {
		return rep
	}
	h, ha := c.HomeAssistant, p.HA()
	// "present" only for a value the agent would send (plugs.HA.TokenState). Of a value it would not send,
	// nothing is said but that: not the value and not its length.
	token, tokenState := "present ("+ha.TokenEnv()+")", ha.TokenState()
	switch tokenState {
	case plugs.TokenMissing:
		token = "missing (" + ha.TokenEnv() + " is not set: fairy-agent secret set " + ha.TokenEnv() + ", then restart the agent)"
	case plugs.TokenUnusable:
		token = "unusable (" + ha.TokenEnv() + " holds a value that cannot be a token: fairy-agent secret set " + ha.TokenEnv() + ", then restart the agent)"
	}
	switching := "off (sockets are shown, nothing is ever switched)"
	if h.Switching {
		switching = fmt.Sprintf("on, %d s between two switches of one socket", h.MinGapS)
	}
	rep.Lines = append(rep.Lines, fmt.Sprintf("home assistant: host %s (%s), token: %s, switching: %s", ha.Host(), ha.Scheme(), token, switching))
	used := map[string]bool{}
	hints, name := c.sourceHints(), ownName()
	var elsewhere []string // the entries with sockets whose system_hint does not mean this machine, in config order
	for _, s := range p.Sockets() {
		rep.Sockets++
		used[s.Entity] = true
		kind := hintKind(hints[s.Source], name)
		if kind == hintOther && !slices.Contains(elsewhere, s.Source) {
			elsewhere = append(elsewhere, s.Source)
		}
		var what string
		switch {
		case s.FeedsSelf:
			what = "never switched (home_assistant.feeds_self)"
		case s.SelfHint && kind == hintName:
			what = "never switched (the system_hint of its power source is this machine's name)"
		case s.SelfHint:
			what = "never switched (its power source says system_hint: self)"
		case !s.Allowed:
			what = "shown only (not in home_assistant.switch_allow)"
		case !h.Switching:
			what = "shown only (home_assistant.switching is false)"
		default:
			what = "can be switched"
			rep.Switchable++
		}
		rep.Lines = append(rep.Lines, fmt.Sprintf("socket \"%s/%s\" (%s): %s, %s", s.Source, s.ID, s.Name, s.Entity, what))
	}
	rep.Never = slices.Clone(h.FeedsSelf)
	never := "none"
	if len(h.FeedsSelf) > 0 {
		never = strings.Join(h.FeedsSelf, ", ")
	}
	rep.Lines = append(rep.Lines, "never switched (feeds_self): "+never)

	if rep.Sockets > 0 || h.Switching {
		switch tokenState {
		case plugs.TokenMissing:
			rep.Notes = append(rep.Notes, "the variable "+ha.TokenEnv()+" holds no token: no socket's state is read and nothing is switched until it does. "+
				"The token the power sources read with is never used in its place.")
		case plugs.TokenUnusable:
			rep.Notes = append(rep.Notes, "the variable "+ha.TokenEnv()+" holds a value that cannot be a token (a space, a line break or a character that is not plain ASCII is in it): "+
				"no socket's state is read and nothing is switched until it holds one. The token the power sources read with is never used in its place.")
		}
	}
	if h.Switching {
		if ha.Scheme() == "http" {
			rep.Notes = append(rep.Notes, "switching goes over http: the token and every request cross that network unencrypted, and whoever is on it can read and change them. "+
				"Use https with ca_file where you can.")
		}
		if approvalState == api.ApprovalOff {
			rep.Notes = append(rep.Notes, "this machine has no passkey check: every switch request is refused (approval_off) until the check is turned on.")
		}
		if approvalState == api.ApprovalBroken {
			rep.Notes = append(rep.Notes, "the passkey check of this machine cannot be used (fairy-agent helper-trust show says why): every switch request is refused until it is repaired.")
		}
	}
	// One variable for both tokens, the normal setup: said once, with the variable's name (as the block writes
	// it), and as a remark. It is no problem and no warning. "One variable" is what this system takes as one
	// (sameEnvName): where letter case tells two names apart, the block's variable is another one than the
	// entries', the block has its own token or none, and the line would be wrong.
	for _, raw := range c.PowerSources {
		if typ, _ := raw["type"].(string); typ != "homeassistant" {
			continue
		}
		if env, _ := raw["token_env"].(string); env != "" && sameEnvName(env, h.TokenEnv) {
			const why = "Home Assistant gives every token of an account the same rights, so a second token only lets you revoke one without the other."
			if h.Switching {
				rep.Remarks = append(rep.Remarks, "switching and reading use the same token ("+h.TokenEnv+"): "+why)
			} else {
				rep.Remarks = append(rep.Remarks, "the sockets' states and the sensors are read with the same token ("+h.TokenEnv+"), and switching would use it too: "+why)
			}
			break
		}
	}
	// A hint that is neither the word self nor this machine's name locks nothing (hintKind). Said for every such
	// entry, whatever its sockets are allowed today: the owner may count on a lock that is not there. The hint
	// itself is not repeated (a value of a homeassistant entry never is).
	for _, id := range elsewhere {
		rep.Notes = append(rep.Notes, "power source "+id+": its system_hint is neither \"self\" nor this machine's name, so this plug is taken as feeding another machine: "+
			"its sockets can be switched if allowed. If it feeds this machine, write system_hint: self, or list its switches in home_assistant.feeds_self.")
	}
	for _, id := range h.SwitchAllow {
		switch {
		case slices.Contains(h.FeedsSelf, id):
			rep.Notes = append(rep.Notes, id+" is in switch_allow and in feeds_self: feeds_self counts, it is never switched.")
		case !used[id]:
			rep.Notes = append(rep.Notes, id+" is in switch_allow and no socket in this file has that switch: nothing is switched by it.")
		}
	}
	return rep
}

// ApprovalStateOnDisk is the state of the passkey check as a look at the trust file files shows it (this
// machine's: ApprovalFiles), for a program that is not the agent (check-config): api.ApprovalOff,
// api.ApprovalRequired or api.ApprovalBroken. Nothing is written and nothing is logged. A caller that may not
// look into the trust file's folder gets "broken", which it should take as "cannot tell".
func ApprovalStateOnDisk(files approval.Files) string {
	g := approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent, ReadOnly: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return g.StatusNow().State
}

// logPlugs writes to the log, once at start, what the config says about the sockets: how many there are, how
// many can be switched, which switches are never switched, each note as a warning and each remark as a line.
func logPlugs(cfg *Config, p *plugs.Plugs, approvalState string) {
	if p == nil {
		return
	}
	rep := cfg.PlugReport(p, approvalState)
	slog.Info("plug sockets (home assistant)", "host", p.HA().Host(), "sockets", rep.Sockets, "can_be_switched", rep.Switchable,
		"never_switched", strings.Join(rep.Never, ","), "switching", cfg.HomeAssistant.Switching, "min_gap_s", cfg.HomeAssistant.MinGapS,
		"token_env", p.HA().TokenEnv(), "token_set", p.HA().TokenSet())
	for _, n := range rep.Notes {
		slog.Warn("plug sockets: " + n)
	}
	for _, n := range rep.Remarks {
		slog.Info("plug sockets: " + n)
	}
}
