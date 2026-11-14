package main

// `fairy-agent helper-run show | cancel`: the run this machine is in (a wake / update / shutdown run of the
// panel), looked at and called off on the machine itself. It reads and changes one file, the run record next
// to the trust file, with the checks the service makes; it starts nothing and talks to nobody.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

const helperRunUsage = `fairy-agent helper-run: the run this machine is in (the panel's "Update unpowered hosts")

  fairy-agent helper-run show   [--config PATH]
  fairy-agent helper-run cancel [--config PATH]

A run starts this machine, and the passkey that started the run signed a ticket for it: unless somebody
confirms the run in the panel with a second passkey check, the machine switches itself off again after the
wait the ticket names, with a notice.
show prints what is on record: armed (and when the self-off begins), counting down, or confirmed (what of the
run is still let through: one update, one shutdown).
cancel (root / Administrator) ends the run on this machine: it does not switch itself off, nothing of the run
is let through any more, and no ticket arms it again until it has been started anew. The service sees the
cancel within a second and stops a countdown that is already running (Windows: shutdown /a does that too).
With no run on record it changes nothing. A record that cannot be read is removed.
The panel's Cancel button for this machine does the same.
`

// runUptime is how long the system has been up, for show (a seam for the tests).
var runUptime = agent.SystemUptime

func helperRunCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "show" && args[0] != "cancel") {
		fmt.Fprint(stderr, helperRunUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("helper-run "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, helperRunUsage) }
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		if err == nil {
			fmt.Fprint(stderr, helperRunUsage)
		}
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "fairy-agent helper-run "+sub+":", err)
		return 1
	}
	if err := adminDataDirTrusted(*cfgPath); err != nil {
		return fail(err)
	}
	cfg, err := agent.Load(*cfgPath)
	if err != nil {
		return fail(fmt.Errorf("config problem: %w", err))
	}
	files := trustFiles(cfg)
	if sub == "cancel" && !trustIsAdmin() {
		return fail(errors.New("run it as root / in an Administrator PowerShell"))
	}
	// (not Windows) the file work is done as the owner of the agent's state folder, as for helper-trust
	as, err := trustBecome(files.Path)
	if err != nil {
		return fail(err)
	}
	if sub == "show" {
		v := files.RunShow()
		fmt.Fprintln(stdout, "run record:     ", v.Path)
		if as != "" {
			fmt.Fprintln(stdout, as)
		}
		printRun(stdout, v)
		return 0
	}
	was, changed, err := files.RunCancel()
	if err != nil {
		return fail(err)
	}
	switch {
	case was.Err != nil:
		fmt.Fprintln(stdout, "the run record could not be read ("+was.Err.Error()+") and was removed. Nothing was armed because of it. What it remembered of earlier runs is gone.")
	case !changed:
		fmt.Fprintln(stdout, "no run is armed or confirmed on this machine ("+was.Path+"): nothing changed")
	default:
		fmt.Fprintln(stdout, "run "+was.ID+" (was "+was.State+") is cancelled on this machine: it does not switch itself off, and nothing of the run is let through any more.")
		fmt.Fprintln(stdout, "The service sees this within a second. No ticket arms this machine again until it has been started anew.")
		if was.State == api.RunOffPending {
			fmt.Fprintln(stdout, "A countdown was running: the service stops it now (Windows, if the helper is not running: shutdown /a).")
		}
	}
	return 0
}

func printRun(w io.Writer, v approval.RunView) {
	switch {
	case v.Err != nil:
		fmt.Fprintln(w, "run:             the record cannot be used:", v.Err)
		fmt.Fprintln(w, "                 nothing is armed and nothing of a run is let through because of it; no ticket is accepted until it is removed: fairy-agent helper-run cancel")
		return
	case !v.Exists:
		fmt.Fprintln(w, "run:             none (no record)")
		return
	}
	left := func() string {
		up, err := runUptime()
		if err != nil {
			return "(this system's uptime cannot be read)"
		}
		d := time.Duration(v.UpMS)*time.Millisecond - up
		if d <= 0 {
			return "now"
		}
		return "in " + d.Round(time.Second).String()
	}
	switch v.State {
	case api.RunArmed:
		fmt.Fprintln(w, "run:             "+v.ID+", armed: this machine switches itself off "+left()+" (then the notice counts down) unless the run is confirmed in the panel or cancelled")
	case api.RunOffPending:
		fmt.Fprintln(w, "run:             "+v.ID+", switching itself off: the countdown ends "+left())
	case api.RunConfirmed:
		to := "no update"
		if v.Update > 0 {
			to = "one update to " + v.To
		}
		fmt.Fprintf(w, "run:             %s, confirmed: still let through without a new approval: %s, %d shutdown; that ends %s\n", v.ID, to, v.Shutdown, left())
	default:
		fmt.Fprintln(w, "run:             none is armed or confirmed")
	}
	if v.Name != "" {
		fmt.Fprintln(w, "signed by:       "+v.Name)
	}
	if v.LastID != "" {
		fmt.Fprintln(w, "last run:        "+v.LastID+", "+v.LastState)
	}
	if v.State != "" { // whether the record is of this boot is the service's to say: it looks at the boot, this command does not
		fmt.Fprintln(w, "                 (a record from before this machine was last started counts for nothing; the service removes it when it starts)")
	}
}
