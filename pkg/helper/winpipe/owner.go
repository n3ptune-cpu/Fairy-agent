package winpipe

import (
	"fmt"
	"sync"
)

// Who owns the pipe the agent connected to? (The decision is here, platform-independent, so both of its modes
// are tested everywhere; Dial in winpipe_windows.go reads the owner from the connected handle.)
//
// Dial knows the helper by the process id the service manager reports for it. A process id can be used again:
// a program that took the pipe's name while the helper was stopped, handed its end of the pipe to a child and
// ended has freed its id, and when the helper later starts with that very id (it restarts at every update),
// the agent takes the stranger's pipe for the helper's. The owner of a pipe cannot be borrowed like that: the
// helper is LocalSystem, so its pipe belongs to Administrators or SYSTEM, and a pipe made by an ordinary
// account's program belongs to that account.
//
// That last sentence has not been seen on a real PC yet. A wrong guess here would cut the agent off from its
// helper on every PC (no fan control, no Core Temp, no shutdown), so in this release the look at the owner
// only reports: a pipe with another owner is used as before and a clear warning goes to the log, once. With
// Enforce (config.yaml: require_helper_pipe_owner: true) such a pipe is refused.

// Well-known owners of a pipe the LocalSystem helper made.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// OwnerCheck is what Dial does about the owner of the pipe it connected to. The zero value reports nothing and
// refuses nothing.
type OwnerCheck struct {
	// Enforce: a pipe whose owner is not SYSTEM or Administrators, or cannot be read, is refused
	// (ErrNotHelper). Off (the default in this release): it is used, and Warn is told.
	Enforce bool
	// Warn gets one sentence when the owner is not as expected; the same sentence only once.
	Warn func(msg string)

	mu   sync.Mutex
	said map[string]bool
	last string
}

// Owner is the owner Decide saw last: a SID, or "unknown (...)" when it could not be read; "" before the first
// look.
func (c *OwnerCheck) Owner() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Decide says whether a connected pipe may be used, given its owner (a SID string) or the error from reading
// it. nil = use it. c may be nil (no look at all).
func (c *OwnerCheck) Decide(pipe, owner string, readErr error) error {
	if c == nil {
		return nil
	}
	seen := owner
	if readErr != nil {
		seen = fmt.Sprintf("unknown (%v)", readErr)
	} else if owner == "" {
		seen = "unknown (the pipe has no owner)"
	}
	c.mu.Lock()
	c.last = seen
	c.mu.Unlock()
	if readErr == nil && (owner == sidSystem || owner == sidAdministrators) {
		return nil
	}
	what := "belongs to " + owner
	if readErr != nil || owner == "" {
		what = "has an owner that cannot be read: " + seen
	}
	if c.Enforce {
		c.warn(fmt.Sprintf("the helper's pipe %s %s. A pipe the fairy-agent-helper service made belongs to SYSTEM or Administrators, "+
			"so this one is not used (require_helper_pipe_owner is on in config.yaml): no fan control, Core Temp or power actions until the helper's own pipe is back. "+
			"Restart the helper (Restart-Service fairy-agent-helper); if this stays, look for the program that holds the pipe's name", pipe, what))
		return fmt.Errorf("%w: its pipe %s, not to SYSTEM or Administrators", ErrNotHelper, what)
	}
	c.warn(fmt.Sprintf("the helper's pipe %s %s, not to SYSTEM or Administrators as a pipe the fairy-agent-helper service made is expected to. "+
		"It is used all the same in this release (the process that serves it is the helper service's own, by its process id). Please report this line; "+
		"to refuse such a pipe, set require_helper_pipe_owner: true in config.yaml and restart the agent", pipe, what))
	return nil
}

func (c *OwnerCheck) warn(msg string) {
	c.mu.Lock()
	if c.said == nil {
		c.said = map[string]bool{}
	}
	again := c.said[msg]
	c.said[msg] = true
	f := c.Warn
	c.mu.Unlock()
	if !again && f != nil {
		f(msg)
	}
}
