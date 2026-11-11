package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Files is the trust file on disk and the checks that say whether it can be believed.
//
// The rule that makes "off" safe: the state is off only when the folder passes CheckDir and holds no file of
// that name. Anything else that is not a usable trust file (a folder others can write, a file that is not a
// plain file of the right owner, unreadable, not valid) is "broken", and broken refuses what trust would have
// required. So trust cannot be switched off by damaging the file, only by removing it, which the folder's
// permissions allow administrators only (Windows) or root and the agent's own user (elsewhere).
type Files struct {
	Path string
	// CheckDir must accept the folder before the file is looked at or written (nil: no check). Windows:
	// collect.TrustedFolder. Elsewhere: UnixCheckDir.
	CheckDir func(dir string) error
	// CheckFile must accept the file before it is read (nil: no check). Windows: collect.TrustedFile.
	// Elsewhere: UnixCheckFile.
	CheckFile func(path string) error
	// Prepare, when set, is called with the temporary file before it gets its final name (the administrator's
	// command on Linux gives the file to root, readable by the agent's group).
	Prepare func(tmp string) error
}

// ErrExists: a trust file is already there.
var ErrExists = errors.New("a trust file exists")

// Load reads the trust file. It returns the state (api.ApprovalOff, ApprovalRequired or ApprovalBroken), the
// trust when the state is required, the file's bytes, and for broken the reason.
func (f Files) Load() (state string, t *Trust, raw []byte, err error) {
	dir := filepath.Dir(f.Path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return api.ApprovalOff, nil, nil, nil // no folder, so no file
	}
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return api.ApprovalBroken, nil, nil, fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	st, err := os.Lstat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return api.ApprovalOff, nil, nil, nil
	}
	if err != nil {
		return api.ApprovalBroken, nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return api.ApprovalBroken, nil, nil, fmt.Errorf("%s is not a plain file", f.Path)
	}
	if f.CheckFile != nil {
		if err := f.CheckFile(f.Path); err != nil {
			return api.ApprovalBroken, nil, nil, fmt.Errorf("the trust file is not safe: %w", err)
		}
	}
	fh, err := os.Open(f.Path)
	if err != nil {
		return api.ApprovalBroken, nil, nil, err
	}
	defer fh.Close()
	raw, err = io.ReadAll(io.LimitReader(fh, maxTrustFile+1))
	if err != nil {
		return api.ApprovalBroken, nil, nil, err
	}
	t, err = ParseTrust(raw)
	if err != nil {
		return api.ApprovalBroken, nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	return api.ApprovalRequired, t, raw, nil
}

// write puts t into a temporary file in the trust file's folder and returns its name.
func (f Files) write(t *Trust) (string, error) {
	dir := filepath.Dir(f.Path)
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return "", fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".approval-trust-*.tmp")
	if err != nil {
		return "", err
	}
	_, err = tmp.Write(t.Marshal())
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && f.Prepare != nil {
		err = f.Prepare(tmp.Name())
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// Create writes the first trust file. It never replaces one: the complete file is written under another name
// and then given its final name with a hard link, which fails when the name is taken (ErrExists). Of two
// callers, in this process or another, exactly one succeeds; a crash at any point leaves either no trust file
// or the complete one.
//
// On Windows this is the mechanism the owner's run of 2026-11-11 proved (the file the helper wrote passed the
// helper's own check: one name, inherited permissions), so it is kept as it is. If the temporary name could
// ever not be removed, the file has two names and the file check says "broken": closed, never open.
func (f Files) Create(t *Trust) error {
	if _, err := os.Lstat(f.Path); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := f.write(t)
	if err != nil {
		return err
	}
	err = os.Link(tmp, f.Path)
	rerr := os.Remove(tmp)
	if errors.Is(err, os.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return err
	}
	if rerr != nil { // the file has a second name: Load's file check decides (Windows refuses it: broken)
		return fmt.Errorf("the trust file was written, but its temporary name could not be removed: %w", rerr)
	}
	syncDir(filepath.Dir(f.Path))
	return nil
}

// Replace writes the trust file, replacing one that is there (the administrator's command only).
func (f Files) Replace(t *Trust) error {
	tmp, err := f.write(t)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, f.Path); err != nil { // replaces a link under the final name, never follows it
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(f.Path))
	return nil
}

// Remove deletes the trust file (the administrator's command only). No file is not an error.
func (f Files) Remove() error {
	if f.CheckDir != nil {
		if err := f.CheckDir(filepath.Dir(f.Path)); err != nil {
			return fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(f.Path))
	return nil
}

// syncDir makes a new or removed name in dir durable where the system can (not on Windows).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// BootMarkName is the file next to the trust file that remembers that the one shutdown without approval
// shortly after boot (the trust file's boot_shutdown_s) was used, and in which boot. It holds no secret.
const BootMarkName = "approval-boot-shutdown.json"

// bootMark is that file.
type bootMark struct {
	// BootID is the system's own id of the boot, where it has one (Linux: /proc/sys/kernel/random/boot_id).
	BootID string `json:"boot_id,omitempty"`
	// UsedAt is when the shutdown was accepted, by this machine's clock (Unix seconds), UptimeS how long the
	// system had been up then.
	UsedAt  int64 `json:"used_at"`
	UptimeS int64 `json:"uptime_s"`
}

func (f Files) bootMarkPath() string { return filepath.Join(filepath.Dir(f.Path), BootMarkName) }

// readBootMark returns the mark, or nil when there is none. An error means "cannot tell": the caller then does
// not accept an unapproved shutdown.
func (f Files) readBootMark() (*bootMark, error) {
	path := f.bootMarkPath()
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a plain file", path)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, 4096))
	if err != nil {
		return nil, err
	}
	var m bootMark
	if err := decodeStrict(b, &m); err != nil || m.UsedAt <= 0 {
		return nil, fmt.Errorf("%s is not readable as the record of a shutdown after boot (remove it to start over)", path)
	}
	return &m, nil
}

// writeBootMark records the mark, replacing an older one, before the shutdown it stands for is accepted.
func (f Files) writeBootMark(m bootMark) error {
	dir := filepath.Dir(f.Path)
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".approval-boot-*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.bootMarkPath())
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	syncDir(dir)
	return nil
}
