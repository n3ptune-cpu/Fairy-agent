package agent

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// HomeAssistantConfig is the block `home_assistant:` of config.yaml: the one Home Assistant whose plug sockets
// this agent shows and, when the owner turns that on here, switches (PLUGS-DESIGN.md, stage 1a).
//
// Every setting of it is the owner's word at the machine. None is ever set through the agent's HTTP routes:
// not the address, not the token, not whether anything is switched, and not which sockets. The panel can ask
// for a socket to be switched; whether that socket can be switched at all is decided by this block alone.
//
//	home_assistant:
//	  url: "http://192.0.2.10:8123"   # Home Assistant itself: http(s)://host[:port], nothing after it
//	  token_env: HA_SWITCH_TOKEN      # NAME of the variable in env_file that holds the token for switching
//	  # ca_file: /etc/fairy-agent/ha.pem   # https only
//	  switching: false                # default: sockets are shown, nothing is ever switched
//	  switch_allow: []                # exact switch.* entity ids that may be switched
//	  feeds_self: []                  # exact switch.* entity ids that are NEVER switched
//	  min_gap_s: 10                   # least time between two switches of one socket
type HomeAssistantConfig struct {
	// URL is Home Assistant itself, by the rule of a homeassistant entry's url (power.HAAddress). The states of
	// the sockets are read from it and the switch requests go to it, and to nothing else.
	URL string `yaml:"url"`
	// TokenEnv names the environment variable that holds the long-lived access token the sockets' states are
	// read with and the sockets are switched with. It is this block's own: the homeassistant entries read their
	// sensors with the token their own token_env names, and nothing ever falls back from one to the other. The
	// owner's plan is a second Home Assistant user for switching, whose token can be revoked alone. While the
	// variable holds nothing, no state is read and nothing is switched.
	TokenEnv string `yaml:"token_env"`
	// CAFile (https only): the certificate, or its CA, that Home Assistant must show.
	CAFile string `yaml:"ca_file"`
	// Switching turns POST /plug/switch on. Default false. true is refused unless the block has a feeds_self
	// line: the owner answers "which socket feeds this machine, Home Assistant or the network" in writing
	// before the first switch, also when the answer is "none" (feeds_self: []).
	Switching bool `yaml:"switching"`
	// SwitchAllow are the entity ids of the switches that may be switched: exact ids, no patterns, at most
	// MaxSwitchList. A socket whose switch is not here is shown and never switched.
	SwitchAllow []string `yaml:"switch_allow"`
	// FeedsSelf are the entity ids of the switches that are never switched, in either direction, whatever
	// SwitchAllow says: the sockets that feed this machine, Home Assistant or the network they talk over.
	FeedsSelf []string `yaml:"feeds_self"`
	// MinGapS is the least time between two switches of one socket (DefaultSwitchGapS; 5 to 3600).
	MinGapS int `yaml:"min_gap_s"`
}

// maxSocketSourceID is the longest id of an entry with sockets.
const maxSocketSourceID = api.MaxSocketSource

const (
	// DefaultSwitchGapS is home_assistant.min_gap_s when the file does not set it.
	DefaultSwitchGapS = 10
	// MaxSwitchList is the most items home_assistant.switch_allow and home_assistant.feeds_self may each have.
	MaxSwitchList = 32
)

// haLines reads two facts from the text of config.yaml that the decoded Config cannot show: whether there is
// a home_assistant block with at least one setting, and whether that block has a feeds_self line whose value
// is a list. `feeds_self: []` is such a line. A missing line is not, and neither is `feeds_self:` with nothing
// after it: the question the line answers ("which sockets must never be switched") is answered by a list, the
// empty one included, and not by leaving the value out.
func haLines(data []byte) (set, feedsSelf bool) {
	var top struct {
		Block map[string]any `yaml:"home_assistant"`
	}
	if yaml.Unmarshal(data, &top) != nil { // the strict decoding has said so
		return false, false
	}
	_, feedsSelf = top.Block["feeds_self"].([]any)
	return len(top.Block) > 0, feedsSelf
}

// HomeAssistantSet reports whether config.yaml has a home_assistant block with at least one setting.
func (c *Config) HomeAssistantSet() bool { return c.haSet }

// validateHomeAssistant checks the home_assistant block. A problem names the setting and, in a list, the
// item's place ("home_assistant.switch_allow, item 2"), never a value: a token or a url with a password that
// was written into the wrong line is not printed (the rule of a homeassistant entry, power.buildHomeAssistant).
//
// Not checked here, because it needs the power sources: that an entry with sockets has this block and the
// same address (Config.NewRelay).
func (c *Config) validateHomeAssistant(add func(string)) {
	h := c.HomeAssistant
	// Also a Config that did not come from a file (haSet is then false) is checked as soon as it has one of the
	// settings: nothing about switching is ever taken unchecked.
	if !c.haSet && h.URL == "" && h.TokenEnv == "" && h.CAFile == "" && !h.Switching && len(h.SwitchAllow) == 0 && len(h.FeedsSelf) == 0 {
		return
	}
	scheme, _, ok := power.HAAddress(h.URL)
	switch {
	case h.URL == "":
		add("home_assistant.url is needed: the address of Home Assistant itself, http(s)://host[:port]")
	case !ok:
		add("home_assistant.url must be the address of Home Assistant itself, http(s)://host[:port], with nothing after it (no path, query, fragment or user)")
	}
	// The token's variable is needed as soon as something would be sent with it: here when switching is on, and
	// in Config.NewRelay when an entry has sockets (their states are read with it). A block with the address
	// alone loads, so that `config set` can write the block one setting at a time, the address first.
	switch {
	case h.TokenEnv == "" && h.Switching:
		add("home_assistant.token_env is needed: the name of the environment variable that holds the token for switching (the token itself does not belong in this file)")
	case h.TokenEnv != "":
		if problem := power.HATokenEnvProblem(h.TokenEnv); problem != "" {
			add("home_assistant." + problem)
		}
	}
	if h.CAFile != "" && ok && scheme != "https" {
		add("home_assistant.ca_file is only for an https url")
	}
	// The line must be there before anything can be switched, and it is asked for by name. The sentence is the
	// one the owner sees from check-config and from `config set home_assistant.switching true`.
	if h.Switching && !c.haFeedsSelf {
		add("home_assistant.switching is true and there is no feeds_self line. Find out which socket feeds this machine, Home Assistant or the network, " +
			"write it into feeds_self, and switch nothing before that. If no socket does, write: feeds_self: []")
	}
	for _, l := range []struct {
		name  string
		items []string
	}{{"switch_allow", h.SwitchAllow}, {"feeds_self", h.FeedsSelf}} {
		if len(l.items) > MaxSwitchList {
			add("home_assistant." + l.name + " has more than " + strconv.Itoa(MaxSwitchList) + " items")
			continue
		}
		at := map[string]int{}
		for i, id := range l.items {
			where := "home_assistant." + l.name + ", item " + strconv.Itoa(i+1)
			switch first, twice := at[id]; {
			case !power.HASwitchEntity(id):
				add(where + ": must be the entity id of a switch in Home Assistant, like switch.desk_plug_socket_1 (the exact id: no pattern, no list in one item)")
			case twice:
				add(where + ": the same id as item " + strconv.Itoa(first))
			default:
				at[id] = i + 1
			}
		}
	}
	if !(h.MinGapS >= 5 && h.MinGapS <= 3600) {
		add("home_assistant.min_gap_s must be 5-3600")
	}
}

// socketChecks are the checks of the entries with sockets that need the whole file (Config.NewRelay makes
// them, so the running agent and check-config do). Each is a config problem: the agent does not start.
//
//   - An entry with sockets needs the home_assistant block with its address and its token's variable, and the
//     entry's own url must be the same scheme, host and port as home_assistant.url. The states of the sockets
//     are read from the block's address with the block's token, and a switch request goes there: a socket is
//     never asked of an address the block does not name.
//   - Its id has at most api.MaxSocketSource (40) characters, where an id may otherwise have 63: the id is
//     part of an approval's text, which must fit into 128 bytes.
//   - One switch belongs to at most one socket of the whole file. Two sockets with one switch would be two
//     names, two tags and two entries of switch_allow's meaning for one thing that is switched.
//
// The errors name entries by their ids and sockets by their place, never an entity id or an address.
func (c *Config) socketChecks(r *Relay) error {
	bScheme, bHost, bOK := power.HAAddress(c.HomeAssistant.URL)
	owner := map[string]string{} // switch entity -> the id of the entry that has it
	for _, src := range r.SocketSources() {
		if !c.haSet || !bOK || src.Scheme != bScheme || !strings.EqualFold(src.Host, bHost) {
			return fmt.Errorf("power source %s: sockets need the home_assistant block, and the entry's url must be the same address as home_assistant.url", src.ID)
		}
		if c.HomeAssistant.TokenEnv == "" {
			return fmt.Errorf("power source %s: sockets need home_assistant.token_env: the states of the sockets are read with that token, not with the entry's", src.ID)
		}
		if len(src.ID) > maxSocketSourceID {
			return fmt.Errorf("power source %s: an entry with sockets needs an id of at most %d characters (the id is part of the text a passkey approval is given for)", src.ID, maxSocketSourceID)
		}
		for i, sock := range src.Sockets {
			if other, taken := owner[sock.SwitchEntity]; taken {
				return fmt.Errorf("power source %s: sockets, item %d: its switch_entity is already the switch of a socket of power source %s; one switch is one socket", src.ID, i+1, other)
			}
			owner[sock.SwitchEntity] = src.ID
		}
	}
	return nil
}
