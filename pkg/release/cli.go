package release

import (
	"bufio"
	"context"
	"crypto/ed25519"
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
}

// Run checks the latest release and, unless Check is set, installs it.
func (c *CLI) Run(ctx context.Context) error {
	fmt.Fprintf(c.Out, "installed: %s %s (%s)\n", c.Program, c.Current, c.Target)
	ch, err := c.Client.Check(ctx, c.Key, c.Program)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "latest:    %s %s (release %s, signature OK)\n", c.Program, ch.Version, ch.Tag)
	cmp, known := Compare(c.Current, ch.Version)
	switch {
	case cmp == 0 && !c.Force:
		fmt.Fprintln(c.Out, "Already up to date.")
		return nil
	case cmp < 0 && !c.Force:
		return fmt.Errorf("the latest release %s is older than the installed %s; not downgrading (--force installs it anyway)", ch.Version, c.Current)
	case !known:
		fmt.Fprintln(c.Out, "(the installed version is not a release build, so it cannot be compared)")
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
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Done: %s %s is running.\n", c.Program, ch.Version)
	return nil
}

func (c *CLI) install(ctx context.Context, ch *Checked) error {
	fmt.Fprintf(c.Out, "downloading %s ...\n", c.Asset)
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
	fmt.Fprintf(c.Out, "verified; installing (the old binary stays as %s.old) and restarting ...\n", c.Target)
	in := c.Installer(c.Target, ch.Version)
	in.Logf = func(f string, a ...any) { fmt.Fprintf(c.Out, "  "+f+"\n", a...) }
	return in.Install(ctx, newPath)
}
