package release

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CLI is the manual update command both programs have, like `tailscale update`: `fairy-agent update` on each
// machine and `fairy update` on the panel host. Both take --check (show installed vs latest), --yes (no
// question) and --force (reinstall the same or an older release).
type CLI struct {
	Client  *Client
	Key     ed25519.PublicKey
	Program string // AgentProgram or PanelProgram
	Current string // the running binary's version
	Target  string // the installed binary
	Asset   string // this platform's release file
	Out     io.Writer
	In      io.Reader
	Check   bool
	Yes     bool
	Force   bool
	// Installer builds the swap / restart / health check for the new version (Healthy may check it).
	Installer func(target, version string) *Installer
	// RunNew runs `<new binary> version` before anything is swapped (the new file must run on this machine).
	RunNew func(path string) (string, error)
	// Done is told the outcome of an install attempt (the agent writes its result file); may be nil.
	Done func(from, to string, err error)
	// Progress is told each step, for a status file (the panel's Update panel button); may be nil:
	// "checking", "up_to_date", "downloading" (to = the new version), "staged" (downloaded and verified),
	// "restarting" (swapped in, starting it), "done", "rolled_back", "failed".
	Progress func(state, to, message string)
}

func (c *CLI) progress(state, to, msg string) {
	if c.Progress != nil {
		c.Progress(state, to, msg)
	}
}

// Run checks the latest release and, unless Check is set, installs it.
func (c *CLI) Run(ctx context.Context) error {
	fmt.Fprintf(c.Out, "installed: %s %s (%s)\n", c.Program, c.Current, c.Target)
	c.progress("checking", "", "asking GitHub for the latest release")
	ch, err := c.Client.Check(ctx, c.Key, c.Program)
	if err != nil {
		c.progress("failed", "", err.Error())
		return err
	}
	fmt.Fprintf(c.Out, "latest:    %s %s (release %s, signature OK)\n", c.Program, ch.Version, ch.Tag)
	cmp, known := Compare(c.Current, ch.Version)
	switch {
	case cmp == 0 && !c.Force:
		fmt.Fprintln(c.Out, "Already up to date.")
		c.progress("up_to_date", ch.Version, "already up to date")
		return nil
	case cmp < 0 && !c.Force:
		err := fmt.Errorf("the latest release %s is older than the installed %s; not downgrading (--force installs it anyway)", ch.Version, c.Current)
		c.progress("failed", ch.Version, err.Error())
		return err
	case !known && !c.Force:
		// never "newer" by default: a release without a build number would otherwise go over any installed one
		err := fmt.Errorf("%w; not installing (--force installs it anyway)", NotComparable(c.Current, ch.Version))
		c.progress("failed", ch.Version, err.Error())
		return err
	case !known:
		fmt.Fprintf(c.Out, "(%v; installing it because of --force)\n", NotComparable(c.Current, ch.Version))
	}
	if c.Check {
		fmt.Fprintf(c.Out, "An update is available: run `%s update` (as root / Administrator) to install it.\n", c.Program)
		return nil
	}
	if !c.Yes {
		fmt.Fprintf(c.Out, "Install %s %s and restart it? [y/N] ", c.Program, ch.Version)
		line, _ := bufio.NewReader(c.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(c.Out, "Nothing changed.")
			return nil
		}
	}
	err = c.install(ctx, ch)
	if c.Done != nil {
		c.Done(c.Current, ch.Version, err)
	}
	var rb *RolledBackError
	switch {
	case errors.As(err, &rb) && rb.RollbackErr == nil:
		c.progress("rolled_back", ch.Version, err.Error())
	case err != nil:
		c.progress("failed", ch.Version, err.Error())
	default:
		c.progress("done", ch.Version, c.Program+" "+ch.Version+" is running")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Done: %s %s is running.\n", c.Program, ch.Version)
	return nil
}

func (c *CLI) install(ctx context.Context, ch *Checked) error {
	fmt.Fprintf(c.Out, "downloading %s ...\n", c.Asset)
	c.progress("downloading", ch.Version, "downloading "+c.Asset)
	newPath, err := c.Client.FetchAsset(ctx, ch, c.Asset, filepath.Dir(c.Target))
	if err != nil {
		return err
	}
	if err := os.Chmod(newPath, 0o755); err != nil {
		os.Remove(newPath)
		return err
	}
	if out, err := c.RunNew(newPath); err != nil || !strings.Contains(out, ch.Version) {
		os.Remove(newPath)
		return fmt.Errorf("the downloaded binary does not run here or reports another version (%q, %v)", strings.TrimSpace(out), err)
	}
	c.progress("staged", ch.Version, "downloaded and verified")
	fmt.Fprintf(c.Out, "verified; installing (the old binary stays as %s.old) and restarting ...\n", c.Target)
	c.progress("restarting", ch.Version, "installing and restarting")
	in := c.Installer(c.Target, ch.Version)
	in.Logf = func(f string, a ...any) { fmt.Fprintf(c.Out, "  "+f+"\n", a...) }
	return in.Install(ctx, newPath)
}
