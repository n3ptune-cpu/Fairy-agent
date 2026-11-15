package agent

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs"
)

// PlugReport is what this machine's config says about its Home Assistant and its sockets, in words: the lines
// check-config prints after its "config OK", and what the agent writes to its log when it starts. It is made
// from the config alone. The token is not read, shown or tried, and Home Assistant is not asked anything.
type PlugReport struct {
	// Lines: one for the home_assistant block, one for each socket, one for the sockets that are never switched.
	Lines []string
	// Notes: what loads and will not do what its owner may expect (check-config prints each after "note: ").
	Notes []string
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
	token := "present (" + ha.TokenEnv() + ")"
	if !ha.TokenSet() {
		token = "missing (" + ha.TokenEnv() + " is not set: fairy-agent secret set " + ha.TokenEnv() + ", then restart the agent)"
	}
	switching := "off (sockets are shown, nothing is ever switched)"
	if h.Switching {
		switching = fmt.Sprintf("on, %d s between two switches of one socket", h.MinGapS)
	}
	rep.Lines = append(rep.Lines, fmt.Sprintf("home assistant: host %s (%s), token: %s, switching: %s", ha.Host(), ha.Scheme(), token, switching))
	used := map[string]bool{}
	for _, s := range p.Sockets() {
		rep.Sockets++
		used[s.Entity] = true
		var what string
		switch {
		case s.FeedsSelf:
			what = "never switched (home_assistant.feeds_self)"
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

	if !ha.TokenSet() && (rep.Sockets > 0 || h.Switching) {
		rep.Notes = append(rep.Notes, "the variable "+ha.TokenEnv()+" holds no token: no socket's state is read and nothing is switched until it does. "+
			"The token the power sources read with is never used in its place.")
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
	for _, raw := range c.PowerSources {
		if typ, _ := raw["type"].(string); typ != "homeassistant" {
			continue
		}
		if env, _ := raw["token_env"].(string); strings.EqualFold(env, h.TokenEnv) {
			rep.Notes = append(rep.Notes, "home_assistant.token_env names the variable the power sources read with: one token reads the sensors and switches the sockets. "+
				"With a second Home Assistant user for switching, its token can be revoked alone, and Home Assistant's own logbook shows which switches came from Fairy.")
			break
		}
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
// many can be switched, which switches are never switched, and each note as a warning.
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
}
