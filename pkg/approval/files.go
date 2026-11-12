package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

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
	// CanKeep, when set, is called by AddMachineID with the trust file's folder and what the trust file is now,
	// before anything is written: an error means that a file made here could not be given the old one's owner
	// and group, and then no temporary file is made and nothing is tried (UnixCanKeep).
	CanKeep func(dir string, old os.FileInfo) error
	// Keep, when set, is called by AddMachineID with the temporary file and what the trust file is now, before
	// the one takes the other's name: it gives the new file the old one's owner, group and mode, or fails
	// (UnixKeep). Windows has neither: a file made in the helper's folder inherits that folder's permissions,
	// as the trust file itself did when it was written.
	Keep func(tmp string, old os.FileInfo) error
}

// ErrExists: a trust file is already there.
var ErrExists = errors.New("a trust file exists")

// Load reads the trust file. It returns the state (api.ApprovalOff, ApprovalRequired or ApprovalBroken), the
// trust when the state is required, the file's bytes, and for broken the reason.
//
// One broken file comes with its content: a file that is good in everything else and has no machine id (the
// error is ErrNoMachineID, t is what it holds). The state is broken all the same, and t must not be used to
// check anything; it is there so that the administrator's command can keep its values when it writes the file
// anew.
func (f Files) Load() (state string, t *Trust, raw []byte, err error) {
	state, raw, _, err = f.read()
	if state != api.ApprovalRequired {
		return state, nil, nil, err
	}
	t, err = ParseTrust(raw)
	if errors.Is(err, ErrNoMachineID) {
		return api.ApprovalBroken, t, raw, fmt.Errorf("%s: %w", f.Path, err)
	}
	if err != nil {
		return api.ApprovalBroken, nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	return api.ApprovalRequired, t, raw, nil
}

// exists reports whether there is anything under the trust file's name. When that cannot be told, the answer
// is yes: the callers treat "no file" as the special case.
func (f Files) exists() bool {
	_, err := os.Lstat(f.Path)
	return !errors.Is(err, os.ErrNotExist)
}

// read is the first half of Load: the checks of the folder and the file, and the file's bytes. The state is
// api.ApprovalRequired when there is a file that passed them (what is in it is not looked at here); st is then
// what the file is.
func (f Files) read() (state string, raw []byte, st os.FileInfo, err error) {
	dir := filepath.Dir(f.Path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return api.ApprovalOff, nil, nil, nil // no folder, so no file
	}
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return api.ApprovalBroken, nil, nil, fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	st, err = os.Lstat(f.Path)
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
	return api.ApprovalRequired, raw, st, nil
}

// AddMachineID gives a trust file from before machine ids its id, once: the file must pass every check, be a
// good trust file in everything else, and have no machine id. It returns the id it added. Only the program
// that owns the file calls it (the Windows helper; elsewhere the agent), when it starts or finds such a file.
//
// Nothing else in the file changes, not a byte: the member is put in right behind the opening brace, and what
// comes out is read back and compared with what went in before it is written. The new content goes into a
// temporary file in the same folder, which gets the old file's owner, group and mode (Keep) and then the old
// file's name, in one step: at every moment the name is either the old file or the complete new one. Where the
// owner could not be kept (CanKeep: root's file, and this process is not root), no temporary file is made at
// all. If the file was changed by somebody else in between (the administrator's command), nothing is written.
// Any failure leaves the file as it was, without an id, and no temporary file behind, and so the state broken:
// nothing is approved, and nothing runs unapproved.
func (f Files) AddMachineID(rnd io.Reader) (string, error) {
	state, raw, st, err := f.read()
	if state != api.ApprovalRequired {
		if err == nil {
			err = errors.New("there is no trust file")
		}
		return "", err
	}
	old, err := ParseTrust(raw)
	if !errors.Is(err, ErrNoMachineID) {
		if err == nil {
			return "", errors.New("the trust file has a machine id already")
		}
		return "", err
	}
	id, err := NewMachineID(rnd)
	if err != nil {
		return "", err
	}
	at := bytes.IndexByte(raw, '{') // the file is one JSON object (ParseTrust), so this is where it opens
	member, _ := json.Marshal(id)
	out := make([]byte, 0, len(raw)+len(member)+32)
	out = append(out, raw[:at+1]...)
	out = append(out, "\n  \"machine_id\": "...)
	out = append(out, member...)
	out = append(out, ',')
	out = append(out, raw[at+1:]...)
	// read back: the same trust with this id and nothing else different
	got, err := ParseTrust(out)
	if err != nil || got.MachineID != id {
		return "", fmt.Errorf("the trust file with a machine id does not read back: %v", err)
	}
	got.MachineID = ""
	if !bytes.Equal(got.Marshal(), old.Marshal()) {
		return "", errors.New("the trust file with a machine id does not read back as the same trust")
	}
	dir := filepath.Dir(f.Path)
	if f.CanKeep != nil { // before the temporary file: where the owner cannot be kept, nothing is written
		if err := f.CanKeep(dir, st); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(dir, trustTempPattern)
	if err != nil {
		return "", sameEveryTime(err)
	}
	renamed := false
	defer func() { // whatever goes wrong from here on, the temporary file does not stay
		if !renamed {
			_ = os.Remove(tmp.Name())
		}
	}()
	_, err = tmp.Write(out)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && f.Keep != nil {
		err = f.Keep(tmp.Name(), st)
	}
	if err == nil {
		// the file must still be the one that was read: the administrator's command may have written another
		var now []byte
		if state, now, _, err = f.read(); err == nil && (state != api.ApprovalRequired || !bytes.Equal(now, raw)) {
			err = errors.New("the trust file was changed in the meantime")
		}
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.Path) // takes the place of the old file under its name, in one step
	}
	if err != nil {
		return "", sameEveryTime(err)
	}
	renamed = true
	syncDir(dir)
	return id, nil
}

// trustTempPattern is the name of a temporary file next to the trust file; "*" is a number made up for each.
const trustTempPattern = ".approval-trust-*.tmp"

var trustTempName = regexp.MustCompile(`\.approval-trust-[0-9]+\.tmp`)

// sameEveryTime is err with the made-up number of a temporary file's name taken out of its text. An attempt
// that keeps failing (AddMachineID is tried again at every look, every five seconds while a panel asks) fails
// with another name each time; with the name in the text, a failure that never changes looked like a new one
// at every look, and the gate, which logs a state once for as long as its reason stays the same, logged it
// every time (second review of 8119ea0..ae9384f, N3).
func sameEveryTime(err error) error {
	if err == nil {
		return nil
	}
	if text := err.Error(); trustTempName.MatchString(text) {
		return errors.New(trustTempName.ReplaceAllString(text, trustTempPattern))
	}
	return err
}

// write puts t into a temporary file in the trust file's folder and returns its name.
func (f Files) write(t *Trust) (string, error) {
	dir := filepath.Dir(f.Path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		// Load calls this state "off" (no folder, so no file); a set finds out here that it cannot be done
		return "", fmt.Errorf("the folder of the trust file does not exist: %s", dir)
	}
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return "", fmt.Errorf("the folder of the trust file is not safe: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, trustTempPattern)
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
